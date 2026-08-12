#!/bin/bash
# Regression probe for the release/tag-push artifact lifecycle.
#
# Runs only in disposable fixture repositories. It uses real Git only for local
# object/index semantics; pushes and GitHub state are intercepted. It never
# builds, signs, notarizes, contacts a network, or mutates a real remote/ref.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/maccrab-release-artifact-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# Must match the three production gates. Fixture builders materialize every
# path so committed-blob verification exercises a complete executor graph.
# BEGIN RELEASE_CRITICAL_EXECUTORS
RELEASE_CRITICAL_EXECUTORS=(
    .githooks/pre-push
    scripts/ci-local.sh
    scripts/release.sh
    scripts/build-release.sh
    scripts/prepare-dmg-payload.sh
    scripts/install.sh
    scripts/release-env.sh
    scripts/_release_env.py
    scripts/export-release-source.py
    scripts/candidate-qualification.py
    scripts/runtime-qualification-workload.sh
    scripts/test-otlp-curl.sh
    scripts/check-release-dependencies.sh
    scripts/prepare-release-pyyaml.sh
    scripts/check-release-pyyaml.sh
    scripts/run-release-python.sh
    scripts/notarize.sh
    scripts/check-rules-trust-anchor.sh
    scripts/_appcast_xml.py
    scripts/generate-appcast-entry.sh
    scripts/publish-appcast-entry.sh
    scripts/publish-release-json.sh
    scripts/publish-cask.sh
    Compiler/compile_rules.py
)
# END RELEASE_CRITICAL_EXECUTORS

install_missing_critical_executor_fixtures() {
    local fixture="$1" path
    for path in "${RELEASE_CRITICAL_EXECUTORS[@]}"; do
        /bin/mkdir -p "$fixture/$(dirname "$path")"
        if [ ! -e "$fixture/$path" ]; then
            printf '#!/bin/bash\nexit 0\n' > "$fixture/$path"
            /bin/chmod 0755 "$fixture/$path"
        fi
    done
}

assert_no_github_delete() {
    local log="$1"
    if [ -f "$log" ] && /usr/bin/grep -qiE -- '(-X|--method)([ =]+)DELETE|release[[:space:]]+delete|unexpected-delete' "$log"; then
        fail "release pipeline attempted an automatic GitHub DELETE: $log"
    fi
}

write_executable() {
    local path="$1"
    shift
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$@" > "$path"
    chmod +x "$path"
}

make_ci_fixture() {
    local fixture="$1"
    mkdir -p "$fixture/.githooks" "$fixture/scripts" "$fixture/fake-bin" \
        "$fixture/Sources" "$fixture/Tools/AssessmentHarness/scripts" "$fixture/tmp"
    cp "$PROJECT_DIR/.githooks/pre-push" "$fixture/.githooks/pre-push"
    cp "$SCRIPT_DIR/ci-local.sh" "$fixture/scripts/ci-local.sh"

    # The artifact lifecycle fixtures do not need a real repository, but the
    # release hook must still see a coherent, stateful object graph: one
    # annotated tag object, its peeled commit, HEAD, and the hook blob in that
    # commit. Dedicated real-Git fixtures below exercise Git's actual object
    # semantics.
    write_executable "$fixture/fake-bin/git" \
        '#!/bin/bash' \
        'tag_object=${MACCRAB_TEST_TAG_OBJECT:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}' \
        'tag_commit=${MACCRAB_TEST_TAG_COMMIT:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}' \
        'head_commit=${MACCRAB_TEST_HEAD_COMMIT:-$tag_commit}' \
        'hook_blob=${MACCRAB_TEST_HOOK_BLOB:-cccccccccccccccccccccccccccccccccccccccc}' \
        'source_tree=${MACCRAB_TEST_SOURCE_TREE:-dddddddddddddddddddddddddddddddddddddddd}' \
        'case "${1:-}" in' \
        '    cat-file)' \
        '        [ "${2:-}" = "-t" ] || exit 2' \
        '        printf "%s\n" "${MACCRAB_TEST_TAG_TYPE:-tag}" ;;' \
        '    rev-parse)' \
        '        case "${2:-}" in' \
        '            HEAD) printf "%s\n" "$head_commit" ;;' \
        '            *:*) printf "%s\n" "$hook_blob" ;;' \
        '            *\^\{tree\}) printf "%s\n" "$source_tree" ;;' \
        '            *\^\{commit\}) printf "%s\n" "$tag_commit" ;;' \
        '            *) printf "%s\n" "$tag_object" ;;' \
        '        esac ;;' \
        '    hash-object) printf "%s\n" "${MACCRAB_TEST_RUNNING_HOOK_BLOB:-$hook_blob}" ;;' \
        '    rev-list) printf "%s\n" "$tag_commit" ;;' \
        '    status)' \
        '        if [ -f .fixture-dirty ] || [ "${MACCRAB_TEST_DIRTY_SOURCE:-0}" = "1" ]; then printf "?? .fixture-dirty\n"; fi ;;' \
        '    *) exit 0 ;;' \
        'esac'

    # Production pins Git and PATH. Only this disposable fixture redirects the
    # copied constants to its stateful shims.
    /usr/bin/sed -i '' \
        -e "s#GIT_BIN=/usr/bin/git#GIT_BIN=${fixture}/fake-bin/git#" \
        -e "s#PATH=/usr/bin:/bin:/usr/sbin:/sbin#PATH=${fixture}/fake-bin:/usr/bin:/bin:/usr/sbin:/sbin#" \
        "$fixture/.githooks/pre-push" "$fixture/scripts/ci-local.sh"

    write_executable "$fixture/fake-bin/swift" \
        '#!/bin/bash' \
        'printf "%s\n" "$*" >> "$MACCRAB_TEST_SWIFT_LOG"' \
        'if [ "${MACCRAB_TEST_RESOLVE_FAIL:-0}" = "1" ] && [ "$*" = "package resolve" ]; then' \
        '    exit 77' \
        'fi' \
        '# ci-local.sh parses this summary to enforce the README tests badge, so the' \
        '# stub must emit the real shape rather than nothing.' \
        'case "$*" in' \
        '    test*) printf "Test run with 1 tests in 1 suites passed after 0.001 seconds.\n" ;;' \
        'esac' \
        'exit 0'
    # Must agree with the stub count above; the badge gate is deliberately exact.
    printf 'fixture README [![Tests](https://img.shields.io/badge/tests-1%%20passing-brightgreen)]()\n' \
        > "$fixture/README.md"
    write_executable "$fixture/fake-bin/python3" \
        '#!/bin/bash' \
        'case "$*" in' \
        '    *compile_rules.py*) printf "Rules compiled: 1\nRules skipped: 0\n" ;;' \
        'esac' \
        'exit 0'
    write_executable "$fixture/fake-bin/mv" \
        '#!/bin/bash' \
        'args=("$@")' \
        'if [ "${1:-}" = "-n" ]; then shift; fi' \
        'source_path=${1:-}' \
        'destination_path=${2:-}' \
        'if [ "${MACCRAB_TEST_STAGE_RENAME_FAIL:-0}" = "1" ] && [[ "$source_path" == .build/MacCrab-v*.dmg ]]; then' \
        '    if [ -d "$destination_path" ]; then destination_path="$destination_path/$(basename "$source_path")"; fi' \
        '    printf "partial-cross-device-copy\n" > "$destination_path"' \
        '    exit 77' \
        'fi' \
        'if [ "${MACCRAB_TEST_ZERO_RESTORE_DESTINATION:-0}" = "1" ] && [[ "$source_path" == */.maccrab-ci-release.*/*.dmg ]] && [[ "$destination_path" == .build/MacCrab-v*.dmg ]]; then' \
        '    /bin/mv "$source_path" "$source_path.recovery"' \
        '    : > "$destination_path"' \
        '    exit 0' \
        'fi' \
        'exec /bin/mv "${args[@]}"'
    # Production pins the rename primitive to /bin/mv. Only this disposable
    # fixture redirects those calls so it can simulate kernel/filesystem faults.
    /usr/bin/sed -i '' \
        "s#/bin/mv -n#${fixture}/fake-bin/mv -n#g" \
        "$fixture/scripts/ci-local.sh"

    local stub
    for stub in \
        rule-lint.sh \
        test-broker-fuzz.sh \
        check-secrets.sh \
        check-release-dependencies.sh \
        test-release-supply-chain.sh \
        test-install-payload.sh \
        test-sqlcipher-provenance.sh \
        test-rules-trust-anchor.sh \
        test-release-artifact-preservation.sh; do
        write_executable "$fixture/scripts/$stub" '#!/bin/bash' 'exit 0'
    done
    printf 'raise SystemExit(0)\n' > "$fixture/scripts/test-candidate-qualification.py"
    write_executable "$fixture/scripts/pre-release-audit.sh" \
        '#!/bin/bash' \
        'if [ "${MACCRAB_TEST_LATE_DELETE:-0}" = "1" ]; then rm -f .build/MacCrab-v*.dmg; fi' \
        'if [ "${MACCRAB_TEST_BREAK_RESTORE:-0}" = "1" ]; then rm -rf .build; printf "not-a-directory\n" > .build; fi' \
        'if [ "${MACCRAB_TEST_DELETE_STAGED:-0}" = "1" ]; then find . -maxdepth 2 -path "./.maccrab-ci-release.*/MacCrab-v*.dmg" -delete; fi' \
        'if [ "${MACCRAB_TEST_SYMLINK_RESTORE:-0}" = "1" ]; then rm -rf .build; mkdir -p redirected-build; ln -s redirected-build .build; fi' \
        'if [ "${MACCRAB_TEST_DIRTY_SOURCE_LATE:-0}" = "1" ]; then : > .fixture-dirty; fi' \
        'exit 0'
    write_executable "$fixture/Tools/AssessmentHarness/scripts/check-harness-isolation.sh" \
        '#!/bin/bash' 'exit 0'
    install_missing_critical_executor_fixtures "$fixture"
}

invoke_tag_hook() {
    local fixture="$1"
    local tag_name="$2"
    (
        cd "$fixture"
        expected_path=${MACCRAB_RELEASE_EXPECTED_DMG:-.build/MacCrab-${tag_name}.dmg}
        expected_sha=${MACCRAB_RELEASE_EXPECTED_SHA256:-$(shasum -a 256 "$expected_path" | awk '{print $1}')}
        expected_commit=${MACCRAB_RELEASE_EXPECTED_COMMIT:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}
        expected_tag_object=${MACCRAB_RELEASE_EXPECTED_TAG_OBJECT:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
        expected_hook_blob=${MACCRAB_RELEASE_EXPECTED_HOOK_BLOB:-cccccccccccccccccccccccccccccccccccccccc}
        expected_source_commit=${MACCRAB_RELEASE_SOURCE_COMMIT:-$expected_commit}
        expected_source_tree=${MACCRAB_RELEASE_SOURCE_TREE:-dddddddddddddddddddddddddddddddddddddddd}
        expected_metadata_tree=${MACCRAB_RELEASE_METADATA_TREE:-$expected_source_tree}
        printf '%s\n' \
            "refs/tags/$tag_name $expected_tag_object refs/tags/$tag_name 0000000000000000000000000000000000000000" \
            | PATH="$fixture/fake-bin:/usr/bin:/bin" \
                TMPDIR="$fixture/tmp" \
                MACCRAB_TEST_LATE_DELETE=1 \
                MACCRAB_TEST_SWIFT_LOG="$fixture/swift.log" \
                MACCRAB_RELEASE_EXPECTED_DMG="$expected_path" \
                MACCRAB_RELEASE_EXPECTED_SHA256="$expected_sha" \
                MACCRAB_RELEASE_EXPECTED_COMMIT="$expected_commit" \
                MACCRAB_RELEASE_EXPECTED_TAG_OBJECT="$expected_tag_object" \
                MACCRAB_RELEASE_EXPECTED_HOOK_BLOB="$expected_hook_blob" \
                MACCRAB_RELEASE_SOURCE_COMMIT="$expected_source_commit" \
                MACCRAB_RELEASE_SOURCE_TREE="$expected_source_tree" \
                MACCRAB_RELEASE_METADATA_TREE="$expected_metadata_tree" \
                ./.githooks/pre-push origin fixture
    )
}

inject_cross_device_stat_fixture() {
    local fixture="$1"
    write_executable "$fixture/fake-bin/stat-device-fixture" \
        '#!/bin/bash' \
        'last=${!#}' \
        'case "$last" in' \
        '    */.maccrab-ci-release.*) printf "999999\n"; exit 0 ;;' \
        'esac' \
        'exec /usr/bin/stat "$@"'
    /usr/bin/sed -i '' \
        "s#/usr/bin/stat -f#${fixture}/fake-bin/stat-device-fixture -f#" \
        "$fixture/scripts/ci-local.sh"
}

invoke_branch_hook() {
    local fixture="$1"
    (
        cd "$fixture"
        printf '%s\n' \
            'refs/heads/dev aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/dev bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
            | PATH="$fixture/fake-bin:/usr/bin:/bin" \
                TMPDIR="$fixture/tmp" \
                MACCRAB_TEST_SWIFT_LOG="$fixture/swift.log" \
                ./.githooks/pre-push origin fixture
    )
}

assert_artifact() {
    local fixture="$1"
    local name="$2"
    local expected="$3"
    [ -f "$fixture/.build/$name" ] || fail "$name was deleted by the clean tag gate"
    [ "$(shasum -a 256 "$fixture/.build/$name" | awk '{print $1}')" = "$expected" ] \
        || fail "$name changed while the clean tag gate ran"
}

# Integrated tag-hook probe: the hook must still request a clean CI run, the
# stale build tree must actually be wiped, and every release DMG must survive
# with identical bytes.
ci_ok="$TEST_ROOT/ci-success"
make_ci_fixture "$ci_ok"
grep -q 'CI_LOCAL_OUTPUT=$(mktemp ' "$ci_ok/scripts/ci-local.sh" \
    || fail "local CI output is not allocated with mktemp"
grep -q 'CI_COMPILED_RULES=$(mktemp -d ' "$ci_ok/scripts/ci-local.sh" \
    || fail "compiled-rule scratch is not allocated with mktemp"
if grep -q '/tmp/ci_local_output.txt\|--output-dir /tmp/ci_compiled_rules' \
        "$ci_ok/scripts/ci-local.sh"; then
    fail "local CI reintroduced a predictable shared-/tmp file or tree"
fi
mkdir -p "$ci_ok/.build"
printf 'signed-notarized-stapled-ga\n' > "$ci_ok/.build/MacCrab-v9.9.9.dmg"
printf 'signed-notarized-stapled-rc\n' > "$ci_ok/.build/MacCrab-v9.9.9-rc.1.dmg"
printf 'stale-object\n' > "$ci_ok/.build/stale-build-object.o"
ga_sha=$(shasum -a 256 "$ci_ok/.build/MacCrab-v9.9.9.dmg" | awk '{print $1}')
rc_sha=$(shasum -a 256 "$ci_ok/.build/MacCrab-v9.9.9-rc.1.dmg" | awk '{print $1}')
invoke_tag_hook "$ci_ok" v9.9.9 > "$ci_ok/output.log" 2>&1 \
    || {
        tail -40 "$ci_ok/output.log" >&2
        fail "tag hook rejected the successful clean-CI fixture"
    }
assert_artifact "$ci_ok" "MacCrab-v9.9.9.dmg" "$ga_sha"
assert_artifact "$ci_ok" "MacCrab-v9.9.9-rc.1.dmg" "$rc_sha"
[ ! -e "$ci_ok/.build/stale-build-object.o" ] \
    || fail "--clean preserved a stale non-release build object"
grep -q '^package resolve$' "$ci_ok/swift.log" \
    || fail "tag hook did not perform a fresh dependency resolve"
if find "$ci_ok" -maxdepth 1 -name '.maccrab-ci-release.*' | grep -q .; then
    fail "successful clean CI left a staged release artifact behind"
fi

# Failure-path probe: set -e used to make cleanup easy to get wrong. Force the
# dependency resolve to fail after .build is deleted and prove the EXIT trap
# restores the notarized DMG while propagating the CI failure.
ci_fail="$TEST_ROOT/ci-resolve-failure"
make_ci_fixture "$ci_fail"
mkdir -p "$ci_fail/.build"
printf 'signed-notarized-stapled-failure-case\n' > "$ci_fail/.build/MacCrab-v9.9.10.dmg"
printf 'stale-object\n' > "$ci_fail/.build/stale-build-object.o"
failure_sha=$(shasum -a 256 "$ci_fail/.build/MacCrab-v9.9.10.dmg" | awk '{print $1}')
set +e
(
    export MACCRAB_TEST_RESOLVE_FAIL=1
    invoke_tag_hook "$ci_fail" v9.9.10
) > "$ci_fail/output.log" 2>&1
failure_status=$?
set -e
[ "$failure_status" -ne 0 ] || fail "tag hook accepted a failed dependency resolve"
assert_artifact "$ci_fail" "MacCrab-v9.9.10.dmg" "$failure_sha"
[ ! -e "$ci_fail/.build/stale-build-object.o" ] \
    || fail "failed --clean run did not wipe the stale build object"
if find "$ci_fail" -maxdepth 1 -name '.maccrab-ci-release.*' | grep -q .; then
    fail "failed clean CI left a staged release artifact behind"
fi

# Restoration must fail closed. Force a late gate to replace `.build` with a
# regular file, making `mkdir -p .build` fail in the EXIT trap. CI must reject
# the push and leave the signed bytes in a printed, recoverable staging path.
ci_restore_fail="$TEST_ROOT/ci-restore-failure"
make_ci_fixture "$ci_restore_fail"
mkdir -p "$ci_restore_fail/.build"
printf 'signed-notarized-stapled-restore-failure\n' > "$ci_restore_fail/.build/MacCrab-v9.9.13.dmg"
restore_failure_sha=$(shasum -a 256 "$ci_restore_fail/.build/MacCrab-v9.9.13.dmg" | awk '{print $1}')
set +e
(
    export MACCRAB_TEST_BREAK_RESTORE=1
    invoke_tag_hook "$ci_restore_fail" v9.9.13
) > "$ci_restore_fail/output.log" 2>&1
restore_failure_status=$?
set -e
[ "$restore_failure_status" -ne 0 ] || fail "tag hook accepted a failed release-artifact restore"
grep -q 'release DMGs remain recoverable at' "$ci_restore_fail/output.log" \
    || fail "failed restore did not print the recovery location"
restore_stage=$(find "$ci_restore_fail" -maxdepth 1 -type d -name '.maccrab-ci-release.*' | head -1)
[ -n "$restore_stage" ] || fail "failed restore discarded its staging directory"
[ "$(shasum -a 256 "$restore_stage/MacCrab-v9.9.13.dmg" | awk '{print $1}')" = "$restore_failure_sha" ] \
    || fail "failed restore did not preserve the original signed bytes"

# Staging must be rename-only. Simulate a cross-device mv that writes a partial
# destination and fails while leaving the sole good source in place. The EXIT
# trap must preserve status 77 and must never restore the partial over the good
# `.build` artifact.
ci_stage_fail="$TEST_ROOT/ci-stage-rename-failure"
make_ci_fixture "$ci_stage_fail"
mkdir -p "$ci_stage_fail/.build"
printf 'signed-notarized-stapled-stage-failure\n' > "$ci_stage_fail/.build/MacCrab-v9.9.14.dmg"
stage_failure_sha=$(shasum -a 256 "$ci_stage_fail/.build/MacCrab-v9.9.14.dmg" | awk '{print $1}')
set +e
(
    export MACCRAB_TEST_STAGE_RENAME_FAIL=1
    invoke_tag_hook "$ci_stage_fail" v9.9.14
) > "$ci_stage_fail/output.log" 2>&1
stage_failure_status=$?
set -e
[ "$stage_failure_status" -eq 77 ] \
    || fail "staging rename failure did not preserve its original exit status (got $stage_failure_status)"
assert_artifact "$ci_stage_fail" "MacCrab-v9.9.14.dmg" "$stage_failure_sha"
grep -q 'staged release artifact is partial' "$ci_stage_fail/output.log" \
    || fail "partial staging destination was not diagnosed"
partial_stage=$(find "$ci_stage_fail" -maxdepth 1 -type d -name '.maccrab-ci-release.*' | head -1)
[ -n "$partial_stage" ] && [ -f "$partial_stage/MacCrab-v9.9.14.dmg" ] \
    || fail "partial staging failure did not retain its diagnostic copy"
[ "$(shasum -a 256 "$partial_stage/MacCrab-v9.9.14.dmg" | awk '{print $1}')" != "$stage_failure_sha" ] \
    || fail "staging failure fixture did not create distinct partial bytes"

# Independently force the st_dev comparison to disagree. The clean gate must
# stop before moving any bytes and remove its still-empty staging directory.
ci_cross_device="$TEST_ROOT/ci-cross-device"
make_ci_fixture "$ci_cross_device"
inject_cross_device_stat_fixture "$ci_cross_device"
mkdir -p "$ci_cross_device/.build"
printf 'signed-notarized-stapled-cross-device\n' > "$ci_cross_device/.build/MacCrab-v9.9.15.dmg"
cross_device_sha=$(shasum -a 256 "$ci_cross_device/.build/MacCrab-v9.9.15.dmg" | awk '{print $1}')
set +e
invoke_tag_hook "$ci_cross_device" v9.9.15 > "$ci_cross_device/output.log" 2>&1
cross_device_status=$?
set -e
[ "$cross_device_status" -ne 0 ] || fail "cross-device preservation was accepted"
assert_artifact "$ci_cross_device" "MacCrab-v9.9.15.dmg" "$cross_device_sha"
grep -q "not on .build's filesystem" "$ci_cross_device/output.log" \
    || fail "cross-device preservation was not diagnosed"
if find "$ci_cross_device" -maxdepth 1 -type d -name '.maccrab-ci-release.*' | grep -q .; then
    fail "cross-device rejection leaked its empty staging directory"
fi

# A staged artifact is part of an exact manifest, not an optional glob. If a
# late gate removes it, restoration and the tag push must fail instead of
# treating an empty staging directory as success.
ci_staged_delete="$TEST_ROOT/ci-staged-delete"
make_ci_fixture "$ci_staged_delete"
mkdir -p "$ci_staged_delete/.build"
printf 'signed-notarized-stapled-staged-delete\n' > "$ci_staged_delete/.build/MacCrab-v9.9.16.dmg"
set +e
(
    export MACCRAB_TEST_DELETE_STAGED=1
    invoke_tag_hook "$ci_staged_delete" v9.9.16
) > "$ci_staged_delete/output.log" 2>&1
staged_delete_status=$?
set -e
[ "$staged_delete_status" -ne 0 ] || fail "tag hook accepted deletion of a manifested staged DMG"
grep -q 'expected release artifact disappeared' "$ci_staged_delete/output.log" \
    || fail "deleted staged DMG was not diagnosed"

# `.build` is an attacker-influenced pathname after arbitrary tests run. A
# directory symlink must not redirect the notarized DMG into another tree.
ci_symlink_restore="$TEST_ROOT/ci-symlink-restore"
make_ci_fixture "$ci_symlink_restore"
mkdir -p "$ci_symlink_restore/.build"
printf 'signed-notarized-stapled-symlink\n' > "$ci_symlink_restore/.build/MacCrab-v9.9.17.dmg"
symlink_restore_sha=$(shasum -a 256 "$ci_symlink_restore/.build/MacCrab-v9.9.17.dmg" | awk '{print $1}')
set +e
(
    export MACCRAB_TEST_SYMLINK_RESTORE=1
    invoke_tag_hook "$ci_symlink_restore" v9.9.17
) > "$ci_symlink_restore/output.log" 2>&1
symlink_restore_status=$?
set -e
[ "$symlink_restore_status" -ne 0 ] || fail "tag hook restored a DMG through symlink .build"
grep -q 'refusing to restore release DMGs through symlink .build' "$ci_symlink_restore/output.log" \
    || fail "symlink restore redirection was not diagnosed"
[ ! -e "$ci_symlink_restore/redirected-build/MacCrab-v9.9.17.dmg" ] \
    || fail "restore followed .build symlink and overwrote the redirected tree"
symlink_stage=$(find "$ci_symlink_restore" -maxdepth 1 -type d -name '.maccrab-ci-release.*' | head -1)
[ -n "$symlink_stage" ] \
    || fail "symlink rejection discarded the recoverable staging directory"
[ "$(shasum -a 256 "$symlink_stage/MacCrab-v9.9.17.dmg" | awk '{print $1}')" = "$symlink_restore_sha" ] \
    || fail "symlink rejection did not retain the original signed bytes"

# A zero-byte pathname is still `-f` and has a valid SHA-256. It must never be
# admitted to the preservation manifest, even when the caller supplies the
# mathematically correct empty-file digest.
ci_zero_pre_stage="$TEST_ROOT/ci-zero-pre-stage"
make_ci_fixture "$ci_zero_pre_stage"
mkdir -p "$ci_zero_pre_stage/.build"
: > "$ci_zero_pre_stage/.build/MacCrab-v9.9.18.dmg"
zero_dmg_sha=$(shasum -a 256 "$ci_zero_pre_stage/.build/MacCrab-v9.9.18.dmg" | awk '{print $1}')
set +e
(
    cd "$ci_zero_pre_stage"
    PATH="$ci_zero_pre_stage/fake-bin:/usr/bin:/bin" \
        TMPDIR="$ci_zero_pre_stage/tmp" \
        MACCRAB_TEST_SWIFT_LOG="$ci_zero_pre_stage/swift.log" \
        ./scripts/ci-local.sh --clean \
            --expect-release-dmg .build/MacCrab-v9.9.18.dmg "$zero_dmg_sha"
) > "$ci_zero_pre_stage/output.log" 2>&1
zero_pre_stage_status=$?
set -e
[ "$zero_pre_stage_status" -ne 0 ] || fail "clean CI admitted a zero-byte release DMG"
grep -q 'required release DMG is missing, empty' "$ci_zero_pre_stage/output.log" \
    || fail "clean CI did not diagnose the zero-byte pre-stage DMG"
[ -f "$ci_zero_pre_stage/.build/MacCrab-v9.9.18.dmg" ] \
    && [ ! -s "$ci_zero_pre_stage/.build/MacCrab-v9.9.18.dmg" ] \
    || fail "zero-byte pre-stage rejection disturbed the original pathname"
if find "$ci_zero_pre_stage" -maxdepth 1 -type d -name '.maccrab-ci-release.*' | grep -q .; then
    fail "zero-byte pre-stage rejection created a staging directory"
fi
set +e
invoke_tag_hook "$ci_zero_pre_stage" v9.9.18 \
    > "$ci_zero_pre_stage/hook-output.log" 2>&1
zero_hook_status=$?
set -e
[ "$zero_hook_status" -ne 0 ] || fail "versioned tag hook admitted a zero-byte release DMG"
grep -q 'tag requires a non-empty regular release DMG' "$ci_zero_pre_stage/hook-output.log" \
    || fail "versioned tag hook did not diagnose the zero-byte DMG"

# Bind the hook/CI handoff to release.sh's pre-tag digest. Even a valid,
# non-empty DMG must not move if its bytes disagree with that caller manifest.
ci_expected_sha_mismatch="$TEST_ROOT/ci-expected-sha-mismatch"
make_ci_fixture "$ci_expected_sha_mismatch"
mkdir -p "$ci_expected_sha_mismatch/.build"
printf 'signed-notarized-stapled-sha-mismatch\n' \
    > "$ci_expected_sha_mismatch/.build/MacCrab-v9.9.19.dmg"
expected_mismatch_sha=$(shasum -a 256 \
    "$ci_expected_sha_mismatch/.build/MacCrab-v9.9.19.dmg" | awk '{print $1}')
set +e
(
    export MACCRAB_RELEASE_EXPECTED_DMG=.build/MacCrab-v9.9.19.dmg
    export MACCRAB_RELEASE_EXPECTED_SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    invoke_tag_hook "$ci_expected_sha_mismatch" v9.9.19
) > "$ci_expected_sha_mismatch/output.log" 2>&1
expected_sha_mismatch_status=$?
set -e
[ "$expected_sha_mismatch_status" -ne 0 ] \
    || fail "tag hook accepted a DMG that disagreed with release.sh's pre-tag digest"
grep -q 'required release DMG changed before clean CI' "$ci_expected_sha_mismatch/output.log" \
    || fail "caller-manifest SHA mismatch was not diagnosed"
assert_artifact "$ci_expected_sha_mismatch" "MacCrab-v9.9.19.dmg" "$expected_mismatch_sha"
if find "$ci_expected_sha_mismatch" -maxdepth 1 -type d -name '.maccrab-ci-release.*' | grep -q .; then
    fail "caller-manifest SHA mismatch moved bytes before rejection"
fi

# The restore postflight independently requires a non-empty regular file. A
# compromised/failed rename that reports success after placing an empty target
# must reject the push and retain the known-good bytes for diagnosis.
ci_zero_restore="$TEST_ROOT/ci-zero-restore"
make_ci_fixture "$ci_zero_restore"
mkdir -p "$ci_zero_restore/.build"
printf 'signed-notarized-stapled-zero-restore\n' \
    > "$ci_zero_restore/.build/MacCrab-v9.9.20.dmg"
zero_restore_sha=$(shasum -a 256 "$ci_zero_restore/.build/MacCrab-v9.9.20.dmg" | awk '{print $1}')
set +e
(
    export MACCRAB_TEST_ZERO_RESTORE_DESTINATION=1
    invoke_tag_hook "$ci_zero_restore" v9.9.20
) > "$ci_zero_restore/output.log" 2>&1
zero_restore_status=$?
set -e
[ "$zero_restore_status" -ne 0 ] || fail "restore postflight accepted a zero-byte DMG"
grep -q 'restored release artifact failed postflight' "$ci_zero_restore/output.log" \
    || fail "zero-byte restore destination was not diagnosed"
[ -f "$ci_zero_restore/.build/MacCrab-v9.9.20.dmg" ] \
    && [ ! -s "$ci_zero_restore/.build/MacCrab-v9.9.20.dmg" ] \
    || fail "zero-restore fixture did not create the rejected empty destination"
zero_restore_stage=$(find "$ci_zero_restore" -maxdepth 1 -type d -name '.maccrab-ci-release.*' | head -1)
[ -n "$zero_restore_stage" ] \
    || fail "zero-byte restore rejection discarded its diagnostic staging directory"
[ "$(shasum -a 256 "$zero_restore_stage/MacCrab-v9.9.20.dmg.recovery" | awk '{print $1}')" = "$zero_restore_sha" ] \
    || fail "zero-byte restore rejection did not retain the known-good bytes"

# The clean gate pins the source snapshot across arbitrary build/test scripts,
# not just at hook entry. A late untracked input must reject the push after the
# exact DMG has been restored.
ci_late_dirty="$TEST_ROOT/ci-late-dirty-source"
make_ci_fixture "$ci_late_dirty"
mkdir -p "$ci_late_dirty/.build"
printf 'signed-notarized-stapled-late-dirty\n' > "$ci_late_dirty/.build/MacCrab-v9.9.21.dmg"
late_dirty_sha=$(shasum -a 256 "$ci_late_dirty/.build/MacCrab-v9.9.21.dmg" | awk '{print $1}')
set +e
(
    export MACCRAB_TEST_DIRTY_SOURCE_LATE=1
    invoke_tag_hook "$ci_late_dirty" v9.9.21
) > "$ci_late_dirty/output.log" 2>&1
late_dirty_status=$?
set -e
[ "$late_dirty_status" -ne 0 ] || fail "clean CI accepted a late untracked release input"
grep -q 'release source snapshot changed during clean CI' "$ci_late_dirty/output.log" \
    || fail "late source mutation was not diagnosed by the commit-pinned gate"
assert_artifact "$ci_late_dirty" "MacCrab-v9.9.21.dmg" "$late_dirty_sha"

# macOS ships Bash 3.2. Under `set -u`, expanding an empty array fails there,
# so exercise the ordinary branch-push path as well as the tag path. It must
# run warm CI and must not resolve dependencies or disturb an existing DMG.
ci_branch="$TEST_ROOT/ci-branch-push"
make_ci_fixture "$ci_branch"
mkdir -p "$ci_branch/.build"
printf 'signed-notarized-stapled-branch-case\n' > "$ci_branch/.build/MacCrab-v9.9.12.dmg"
printf 'warm-object-must-survive\n' > "$ci_branch/.build/warm-build-object.o"
branch_sha=$(shasum -a 256 "$ci_branch/.build/MacCrab-v9.9.12.dmg" | awk '{print $1}')
invoke_branch_hook "$ci_branch" > "$ci_branch/output.log" 2>&1 \
    || fail "ordinary branch push did not run warm local CI"
assert_artifact "$ci_branch" "MacCrab-v9.9.12.dmg" "$branch_sha"
if [ -s "$ci_branch/swift.log" ] && grep -q '^package resolve$' "$ci_branch/swift.log"; then
    fail "ordinary branch push unexpectedly requested a clean dependency resolve"
fi
[ -f "$ci_branch/.build/warm-build-object.o" ] \
    || fail "ordinary branch push unexpectedly wiped the warm build tree"
for expected_swift in 'build' 'build --build-tests' 'test --no-parallel'; do
    grep -q "^${expected_swift}$" "$ci_branch/swift.log" \
        || fail "ordinary branch hook did not run swift $expected_swift"
done

# Exercise the release-ref policy against Git's real object database in fully
# disposable repositories. These probes never contact a remote: they feed the
# documented pre-push stdin protocol directly to the hook.
make_real_hook_repo() {
    local fixture="$1"
    mkdir -p "$fixture/.githooks" "$fixture/scripts" "$fixture/.build"
    cp "$PROJECT_DIR/.githooks/pre-push" "$fixture/.githooks/pre-push"
    write_executable "$fixture/scripts/ci-local.sh" \
        '#!/bin/bash' \
        'printf "%s\n" "$*" >> "$MACCRAB_TEST_CI_LOG"' \
        'exit 0'
    printf '.build/\n*.log\n' > "$fixture/.gitignore"
    printf 'fixture\n' > "$fixture/source.txt"
    install_missing_critical_executor_fixtures "$fixture"
    (
        cd "$fixture"
        /usr/bin/git init -q
        /usr/bin/git config user.name 'MacCrab fixture'
        /usr/bin/git config user.email 'fixture@invalid.example'
        /usr/bin/git config user.signingkey ''
        /usr/bin/git config commit.gpgSign false
        /usr/bin/git config tag.gpgSign false
        /usr/bin/git config core.hooksPath .no-hooks
        /usr/bin/git add .
        /usr/bin/git commit -q -m 'fixture root'
    )
}

real_tag_manifest() {
    local fixture="$1"
    local tag="$2"
    local tag_object commit tree hook_blob dmg_path dmg_sha
    tag_object=$(/usr/bin/git -C "$fixture" rev-parse "refs/tags/$tag")
    commit=$(/usr/bin/git -C "$fixture" rev-parse "$tag_object^{commit}")
    tree=$(/usr/bin/git -C "$fixture" rev-parse "$commit^{tree}")
    hook_blob=$(/usr/bin/git -C "$fixture" rev-parse "$commit:.githooks/pre-push")
    dmg_path=".build/MacCrab-${tag}.dmg"
    dmg_sha=$(/usr/bin/shasum -a 256 "$fixture/$dmg_path" | /usr/bin/awk '{print $1}')
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$tag_object" "$commit" "$tree" "$hook_blob" "$dmg_path" "$dmg_sha"
}

invoke_real_tag_hook() {
    local fixture="$1"
    local tag="$2"
    local tag_object="$3"
    local commit="$4"
    local tree="$5"
    local hook_blob="$6"
    local dmg_path="$7"
    local dmg_sha="$8"
    local manifest_tag_object="${9:-$tag_object}"
    local manifest_commit="${10:-$commit}"
    local manifest_source_commit="${11:-$commit}"
    local manifest_source_tree="${12:-$tree}"
    local manifest_metadata_tree="${13:-$tree}"
    (
        cd "$fixture"
        printf 'refs/tags/%s %s refs/tags/%s %040d\n' "$tag" "$tag_object" "$tag" 0 \
            | MACCRAB_TEST_CI_LOG="$TEST_ROOT/real-hook-ci.log" \
                MACCRAB_RELEASE_EXPECTED_DMG="$dmg_path" \
                MACCRAB_RELEASE_EXPECTED_SHA256="$dmg_sha" \
                MACCRAB_RELEASE_EXPECTED_COMMIT="$manifest_commit" \
                MACCRAB_RELEASE_EXPECTED_TAG_OBJECT="$manifest_tag_object" \
                MACCRAB_RELEASE_EXPECTED_HOOK_BLOB="$hook_blob" \
                MACCRAB_RELEASE_SOURCE_COMMIT="$manifest_source_commit" \
                MACCRAB_RELEASE_SOURCE_TREE="$manifest_source_tree" \
                MACCRAB_RELEASE_METADATA_TREE="$manifest_metadata_tree" \
                ./.githooks/pre-push origin fixture
    )
}

real_hook_ok="$TEST_ROOT/real-hook-success"
make_real_hook_repo "$real_hook_ok"
printf 'real annotated release bytes\n' > "$real_hook_ok/.build/MacCrab-v9.8.1.dmg"
/usr/bin/git -C "$real_hook_ok" tag -a v9.8.1 -m 'fixture v9.8.1'
IFS=$'\t' read -r real_tag_object real_commit real_tree real_hook_blob real_dmg_path real_dmg_sha \
    <<< "$(real_tag_manifest "$real_hook_ok" v9.8.1)"
invoke_real_tag_hook "$real_hook_ok" v9.8.1 "$real_tag_object" "$real_commit" \
    "$real_tree" "$real_hook_blob" "$real_dmg_path" "$real_dmg_sha" \
    > "$real_hook_ok/output.log" 2>&1 \
    || {
        tail -40 "$real_hook_ok/output.log" >&2
        fail "real Git annotated-tag fixture was rejected"
    }
grep -q -- "--expect-release-commit $real_commit" "$TEST_ROOT/real-hook-ci.log" \
    || fail "real Git tag fixture did not pin clean CI to the peeled commit"
grep -q -- "--expect-release-dmg $real_dmg_path $real_dmg_sha" "$TEST_ROOT/real-hook-ci.log" \
    || fail "real Git tag fixture did not pass the exact artifact manifest"
grep -q -- "--expect-release-source $real_commit $real_tree --expect-release-metadata-tree $real_tree" \
        "$TEST_ROOT/real-hook-ci.log" \
    || fail "real Git tag fixture omitted source/tree binding from clean CI"

real_hook_old="$TEST_ROOT/real-hook-old-commit"
make_real_hook_repo "$real_hook_old"
printf 'old commit release bytes\n' > "$real_hook_old/.build/MacCrab-v9.8.2.dmg"
/usr/bin/git -C "$real_hook_old" tag -a v9.8.2 -m 'old commit tag'
IFS=$'\t' read -r old_tag_object old_commit old_tree old_hook_blob old_dmg_path old_dmg_sha \
    <<< "$(real_tag_manifest "$real_hook_old" v9.8.2)"
printf 'new head\n' >> "$real_hook_old/source.txt"
/usr/bin/git -C "$real_hook_old" add source.txt
/usr/bin/git -C "$real_hook_old" commit -q -m 'advance head'
set +e
invoke_real_tag_hook "$real_hook_old" v9.8.2 "$old_tag_object" "$old_commit" \
    "$old_tree" "$old_hook_blob" "$old_dmg_path" "$old_dmg_sha" \
    > "$real_hook_old/output.log" 2>&1
old_commit_status=$?
set -e
[ "$old_commit_status" -ne 0 ] || fail "tagging an old commit while HEAD advanced was accepted"
grep -q 'pushed tag, commit, HEAD' "$real_hook_old/output.log" \
    || fail "old-tag/current-HEAD mismatch was not diagnosed"

real_hook_light="$TEST_ROOT/real-hook-lightweight"
make_real_hook_repo "$real_hook_light"
printf 'lightweight release bytes\n' > "$real_hook_light/.build/MacCrab-v9.8.3.dmg"
/usr/bin/git -C "$real_hook_light" tag v9.8.3
light_object=$(/usr/bin/git -C "$real_hook_light" rev-parse refs/tags/v9.8.3)
light_commit=$(/usr/bin/git -C "$real_hook_light" rev-parse HEAD)
light_tree=$(/usr/bin/git -C "$real_hook_light" rev-parse "$light_commit^{tree}")
light_hook=$(/usr/bin/git -C "$real_hook_light" rev-parse "$light_commit:.githooks/pre-push")
light_sha=$(/usr/bin/shasum -a 256 "$real_hook_light/.build/MacCrab-v9.8.3.dmg" | /usr/bin/awk '{print $1}')
set +e
invoke_real_tag_hook "$real_hook_light" v9.8.3 "$light_object" "$light_commit" \
    "$light_tree" "$light_hook" .build/MacCrab-v9.8.3.dmg "$light_sha" \
    > "$real_hook_light/output.log" 2>&1
light_status=$?
set -e
[ "$light_status" -ne 0 ] || fail "lightweight release tag was accepted"
grep -q 'must be an annotated tag object' "$real_hook_light/output.log" \
    || fail "lightweight tag rejection was not diagnosed"

real_hook_missing="$TEST_ROOT/real-hook-missing-manifest"
make_real_hook_repo "$real_hook_missing"
printf 'missing manifest bytes\n' > "$real_hook_missing/.build/MacCrab-v9.8.4.dmg"
/usr/bin/git -C "$real_hook_missing" tag -a v9.8.4 -m 'missing manifest'
missing_object=$(/usr/bin/git -C "$real_hook_missing" rev-parse refs/tags/v9.8.4)
set +e
(
    cd "$real_hook_missing"
    printf 'refs/tags/v9.8.4 %s refs/tags/v9.8.4 %040d\n' "$missing_object" 0 \
        | ./.githooks/pre-push origin fixture
) > "$real_hook_missing/output.log" 2>&1
missing_manifest_status=$?
set -e
[ "$missing_manifest_status" -ne 0 ] || fail "release tag without a manifest was accepted"
grep -q 'require DMG, final/source commit, source/metadata tree' "$real_hook_missing/output.log" \
    || fail "missing release manifest was not diagnosed"
missing_commit=$(/usr/bin/git -C "$real_hook_missing" rev-parse "$missing_object^{commit}")
missing_sha=$(/usr/bin/shasum -a 256 "$real_hook_missing/.build/MacCrab-v9.8.4.dmg" | /usr/bin/awk '{print $1}')
set +e
(
    cd "$real_hook_missing"
    printf 'refs/tags/v9.8.4 %s refs/tags/v9.8.4 %040d\n' "$missing_object" 0 \
        | MACCRAB_RELEASE_EXPECTED_DMG=.build/MacCrab-v9.8.4.dmg \
            MACCRAB_RELEASE_EXPECTED_SHA256="$missing_sha" \
            MACCRAB_RELEASE_EXPECTED_COMMIT="$missing_commit" \
            MACCRAB_RELEASE_EXPECTED_TAG_OBJECT="$missing_object" \
            ./.githooks/pre-push origin fixture
) > "$real_hook_missing/partial.log" 2>&1
partial_manifest_status=$?
set -e
[ "$partial_manifest_status" -ne 0 ] || fail "partial release manifest without hook blob was accepted"

real_hook_wrong="$TEST_ROOT/real-hook-wrong-manifest"
make_real_hook_repo "$real_hook_wrong"
printf 'wrong manifest bytes\n' > "$real_hook_wrong/.build/MacCrab-v9.8.5.dmg"
/usr/bin/git -C "$real_hook_wrong" tag -a v9.8.5 -m 'wrong manifest'
IFS=$'\t' read -r wrong_tag_object wrong_commit wrong_tree wrong_hook_blob wrong_dmg_path wrong_dmg_sha \
    <<< "$(real_tag_manifest "$real_hook_wrong" v9.8.5)"
set +e
invoke_real_tag_hook "$real_hook_wrong" v9.8.5 "$wrong_tag_object" "$wrong_commit" \
    "$wrong_tree" dddddddddddddddddddddddddddddddddddddddd "$wrong_dmg_path" "$wrong_dmg_sha" \
    > "$real_hook_wrong/output.log" 2>&1
wrong_manifest_status=$?
set -e
[ "$wrong_manifest_status" -ne 0 ] || fail "wrong hook-blob manifest was accepted"
set +e
invoke_real_tag_hook "$real_hook_wrong" v9.8.5 "$wrong_tag_object" "$wrong_commit" \
    "$wrong_tree" "$wrong_hook_blob" "$wrong_dmg_path" "$wrong_dmg_sha" \
    eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
    > "$real_hook_wrong/wrong-tag.log" 2>&1
wrong_tag_manifest_status=$?
invoke_real_tag_hook "$real_hook_wrong" v9.8.5 "$wrong_tag_object" "$wrong_commit" \
    "$wrong_tree" "$wrong_hook_blob" "$wrong_dmg_path" "$wrong_dmg_sha" \
    "$wrong_tag_object" ffffffffffffffffffffffffffffffffffffffff \
    > "$real_hook_wrong/wrong-commit.log" 2>&1
wrong_commit_manifest_status=$?
set -e
[ "$wrong_tag_manifest_status" -ne 0 ] || fail "wrong tag-object manifest was accepted"
[ "$wrong_commit_manifest_status" -ne 0 ] || fail "wrong commit manifest was accepted"
set +e
invoke_real_tag_hook "$real_hook_wrong" v9.8.5 "$wrong_tag_object" "$wrong_commit" \
    "$wrong_tree" "$wrong_hook_blob" "$wrong_dmg_path" "$wrong_dmg_sha" \
    "$wrong_tag_object" "$wrong_commit" ffffffffffffffffffffffffffffffffffffffff \
    "$wrong_tree" "$wrong_tree" > "$real_hook_wrong/wrong-source-commit.log" 2>&1
wrong_source_commit_status=$?
invoke_real_tag_hook "$real_hook_wrong" v9.8.5 "$wrong_tag_object" "$wrong_commit" \
    "$wrong_tree" "$wrong_hook_blob" "$wrong_dmg_path" "$wrong_dmg_sha" \
    "$wrong_tag_object" "$wrong_commit" "$wrong_commit" \
    ffffffffffffffffffffffffffffffffffffffff "$wrong_tree" \
    > "$real_hook_wrong/wrong-source-tree.log" 2>&1
wrong_source_tree_status=$?
invoke_real_tag_hook "$real_hook_wrong" v9.8.5 "$wrong_tag_object" "$wrong_commit" \
    "$wrong_tree" "$wrong_hook_blob" "$wrong_dmg_path" "$wrong_dmg_sha" \
    "$wrong_tag_object" "$wrong_commit" "$wrong_commit" "$wrong_tree" \
    ffffffffffffffffffffffffffffffffffffffff \
    > "$real_hook_wrong/wrong-metadata-tree.log" 2>&1
wrong_metadata_tree_status=$?
set -e
[ "$wrong_source_commit_status" -ne 0 ] || fail "wrong source commit manifest was accepted"
[ "$wrong_source_tree_status" -ne 0 ] || fail "wrong source tree manifest was accepted"
[ "$wrong_metadata_tree_status" -ne 0 ] || fail "wrong metadata tree manifest was accepted"

real_hook_dirty="$TEST_ROOT/real-hook-dirty-source"
make_real_hook_repo "$real_hook_dirty"
printf 'dirty manifest bytes\n' > "$real_hook_dirty/.build/MacCrab-v9.8.6.dmg"
/usr/bin/git -C "$real_hook_dirty" tag -a v9.8.6 -m 'dirty source'
IFS=$'\t' read -r dirty_tag_object dirty_commit dirty_tree dirty_hook_blob dirty_dmg_path dirty_dmg_sha \
    <<< "$(real_tag_manifest "$real_hook_dirty" v9.8.6)"
printf 'untracked source input\n' > "$real_hook_dirty/untracked.swift"
set +e
invoke_real_tag_hook "$real_hook_dirty" v9.8.6 "$dirty_tag_object" "$dirty_commit" \
    "$dirty_tree" "$dirty_hook_blob" "$dirty_dmg_path" "$dirty_dmg_sha" \
    > "$real_hook_dirty/output.log" 2>&1
dirty_source_status=$?
set -e
[ "$dirty_source_status" -ne 0 ] || fail "release tag with an untracked source input was accepted"
grep -q 'source is dirty or has untracked inputs' "$real_hook_dirty/output.log" \
    || fail "untracked release input was not diagnosed"

real_hook_mutated="$TEST_ROOT/real-hook-mutated-hook"
make_real_hook_repo "$real_hook_mutated"
printf 'mutated hook bytes\n' > "$real_hook_mutated/.build/MacCrab-v9.8.7.dmg"
/usr/bin/git -C "$real_hook_mutated" tag -a v9.8.7 -m 'hook mutation'
IFS=$'\t' read -r mutated_tag_object mutated_commit mutated_tree mutated_hook_blob mutated_dmg_path mutated_dmg_sha \
    <<< "$(real_tag_manifest "$real_hook_mutated" v9.8.7)"
printf '\n# fixture mutation\n' >> "$real_hook_mutated/.githooks/pre-push"
set +e
invoke_real_tag_hook "$real_hook_mutated" v9.8.7 "$mutated_tag_object" "$mutated_commit" \
    "$mutated_tree" "$mutated_hook_blob" "$mutated_dmg_path" "$mutated_dmg_sha" \
    > "$real_hook_mutated/output.log" 2>&1
mutated_hook_status=$?
set -e
[ "$mutated_hook_status" -ne 0 ] || fail "release tag with mutated executing hook was accepted"

# `git status` deliberately hides assume-unchanged and skip-worktree changes.
# Exercise the real index flags against critical executors so the release hook's
# ls-files -v + really-refresh + blob checks cannot be replaced by porcelain.
for hidden_mode in assume-unchanged skip-worktree both; do
    hidden_fixture="$TEST_ROOT/real-hook-hidden-${hidden_mode}"
    make_real_hook_repo "$hidden_fixture"
    printf 'hidden flag release bytes\n' > "$hidden_fixture/.build/MacCrab-v9.8.70.dmg"
    /usr/bin/git -C "$hidden_fixture" tag -a v9.8.70 -m "hidden $hidden_mode"
    IFS=$'\t' read -r hidden_tag hidden_commit hidden_tree hidden_hook hidden_dmg hidden_sha \
        <<< "$(real_tag_manifest "$hidden_fixture" v9.8.70)"
    hidden_path=scripts/build-release.sh
    case "$hidden_mode" in
        assume-unchanged)
            /usr/bin/git -C "$hidden_fixture" update-index --assume-unchanged "$hidden_path" ;;
        skip-worktree)
            /usr/bin/git -C "$hidden_fixture" update-index --skip-worktree "$hidden_path" ;;
        both)
            /usr/bin/git -C "$hidden_fixture" update-index --assume-unchanged "$hidden_path"
            /usr/bin/git -C "$hidden_fixture" update-index --skip-worktree "$hidden_path" ;;
    esac
    printf '\n# hidden executor mutation\n' >> "$hidden_fixture/$hidden_path"
    [ -z "$(/usr/bin/git -C "$hidden_fixture" status --porcelain)" ] \
        || fail "$hidden_mode fixture was not hidden from git status"
    set +e
    invoke_real_tag_hook "$hidden_fixture" v9.8.70 "$hidden_tag" "$hidden_commit" \
        "$hidden_tree" "$hidden_hook" "$hidden_dmg" "$hidden_sha" \
        > "$hidden_fixture/output.log" 2>&1
    hidden_status=$?
    set -e
    [ "$hidden_status" -ne 0 ] || fail "hook accepted $hidden_mode critical-executor mutation"
    /usr/bin/grep -q 'assume-unchanged/skip-worktree' "$hidden_fixture/output.log" \
        || fail "hook did not diagnose $hidden_mode index state"
done

# ci-local's release mode independently rejects the same hidden-index attack;
# the hook is not its only line of defense.
for hidden_mode in assume-unchanged skip-worktree both; do
    ci_hidden="$TEST_ROOT/real-ci-hidden-${hidden_mode}"
    /bin/mkdir -p "$ci_hidden/scripts" "$ci_hidden/.githooks" "$ci_hidden/.build"
    /bin/cp "$SCRIPT_DIR/ci-local.sh" "$ci_hidden/scripts/ci-local.sh"
    /bin/cp "$PROJECT_DIR/.githooks/pre-push" "$ci_hidden/.githooks/pre-push"
    install_missing_critical_executor_fixtures "$ci_hidden"
    printf '.build/\n*.log\n' > "$ci_hidden/.gitignore"
    (
        cd "$ci_hidden"
        /usr/bin/git init -q
        /usr/bin/git config user.name 'MacCrab CI hidden fixture'
        /usr/bin/git config user.email 'ci-hidden@invalid.example'
        /usr/bin/git config core.hooksPath .no-hooks
        /usr/bin/git add .
        /usr/bin/git commit -q -m root
    )
    ci_hidden_commit=$(/usr/bin/git -C "$ci_hidden" rev-parse HEAD)
    ci_hidden_tree=$(/usr/bin/git -C "$ci_hidden" rev-parse "$ci_hidden_commit^{tree}")
    ci_hidden_path=scripts/build-release.sh
    case "$hidden_mode" in
        assume-unchanged)
            /usr/bin/git -C "$ci_hidden" update-index --assume-unchanged "$ci_hidden_path" ;;
        skip-worktree)
            /usr/bin/git -C "$ci_hidden" update-index --skip-worktree "$ci_hidden_path" ;;
        both)
            /usr/bin/git -C "$ci_hidden" update-index --assume-unchanged "$ci_hidden_path"
            /usr/bin/git -C "$ci_hidden" update-index --skip-worktree "$ci_hidden_path" ;;
    esac
    printf '\n# hidden direct-CI mutation\n' >> "$ci_hidden/$ci_hidden_path"
    [ -z "$(/usr/bin/git -C "$ci_hidden" status --porcelain)" ] \
        || fail "direct CI $hidden_mode fixture was visible to git status"
    printf 'direct CI hidden DMG\n' > "$ci_hidden/.build/MacCrab-v9.8.71.dmg"
    ci_hidden_sha=$(/usr/bin/shasum -a 256 "$ci_hidden/.build/MacCrab-v9.8.71.dmg" \
        | /usr/bin/awk '{print $1}')
    set +e
    (
        cd "$ci_hidden"
        ./scripts/ci-local.sh --clean \
            --expect-release-commit "$ci_hidden_commit" \
            --expect-release-source "$ci_hidden_commit" "$ci_hidden_tree" \
            --expect-release-metadata-tree "$ci_hidden_tree" \
            --expect-release-dmg .build/MacCrab-v9.8.71.dmg "$ci_hidden_sha"
    ) > "$ci_hidden/output.log" 2>&1
    ci_hidden_status=$?
    set -e
    [ "$ci_hidden_status" -ne 0 ] \
        || fail "ci-local release mode accepted $hidden_mode executor mutation"
    /usr/bin/grep -q 'assume-unchanged/skip-worktree' "$ci_hidden/output.log" \
        || fail "ci-local did not diagnose $hidden_mode index state"
done

real_hook_extra_metadata="$TEST_ROOT/real-hook-extra-metadata-path"
make_real_hook_repo "$real_hook_extra_metadata"
/bin/mkdir -p "$real_hook_extra_metadata/Casks" "$real_hook_extra_metadata/homebrew"
printf 'old\n' > "$real_hook_extra_metadata/release.json"
printf 'old\n' > "$real_hook_extra_metadata/Casks/maccrab.rb"
printf 'old\n' > "$real_hook_extra_metadata/homebrew/maccrab.rb"
/usr/bin/git -C "$real_hook_extra_metadata" add release.json Casks homebrew
/usr/bin/git -C "$real_hook_extra_metadata" -c core.hooksPath=.no-hooks \
    commit -q -m 'metadata source'
extra_source_commit=$(/usr/bin/git -C "$real_hook_extra_metadata" rev-parse HEAD)
extra_source_tree=$(/usr/bin/git -C "$real_hook_extra_metadata" rev-parse "$extra_source_commit^{tree}")
printf 'new\n' > "$real_hook_extra_metadata/release.json"
printf 'new\n' > "$real_hook_extra_metadata/Casks/maccrab.rb"
printf 'new\n' > "$real_hook_extra_metadata/homebrew/maccrab.rb"
printf 'unauthorized metadata-side source mutation\n' >> "$real_hook_extra_metadata/source.txt"
/usr/bin/git -C "$real_hook_extra_metadata" add release.json Casks homebrew source.txt
/usr/bin/git -C "$real_hook_extra_metadata" -c core.hooksPath=.no-hooks \
    commit -q -m 'metadata plus extra path'
printf 'extra metadata release bytes\n' \
    > "$real_hook_extra_metadata/.build/MacCrab-v9.8.72.dmg"
/usr/bin/git -C "$real_hook_extra_metadata" tag -a v9.8.72 -m 'extra metadata path'
IFS=$'\t' read -r extra_tag extra_final extra_tree extra_hook extra_dmg extra_sha \
    <<< "$(real_tag_manifest "$real_hook_extra_metadata" v9.8.72)"
set +e
invoke_real_tag_hook "$real_hook_extra_metadata" v9.8.72 "$extra_tag" "$extra_final" \
    "$extra_tree" "$extra_hook" "$extra_dmg" "$extra_sha" \
    "$extra_tag" "$extra_final" "$extra_source_commit" "$extra_source_tree" "$extra_tree" \
    > "$real_hook_extra_metadata/output.log" 2>&1
extra_metadata_status=$?
set -e
[ "$extra_metadata_status" -ne 0 ] || fail "hook accepted an extra metadata-commit path"
/usr/bin/grep -q 'outside the exact GA allowlist' "$real_hook_extra_metadata/output.log" \
    || fail "extra metadata path was not diagnosed"

real_hook_multi="$TEST_ROOT/real-hook-multi-tag"
make_real_hook_repo "$real_hook_multi"
printf 'multi one\n' > "$real_hook_multi/.build/MacCrab-v9.8.8.dmg"
printf 'multi two\n' > "$real_hook_multi/.build/MacCrab-v9.8.9.dmg"
/usr/bin/git -C "$real_hook_multi" tag -a v9.8.8 -m one
/usr/bin/git -C "$real_hook_multi" tag -a v9.8.9 -m two
multi_one=$(/usr/bin/git -C "$real_hook_multi" rev-parse refs/tags/v9.8.8)
multi_two=$(/usr/bin/git -C "$real_hook_multi" rev-parse refs/tags/v9.8.9)
set +e
(
    cd "$real_hook_multi"
    {
        printf 'refs/tags/v9.8.8 %s refs/tags/v9.8.8 %040d\n' "$multi_one" 0
        printf 'refs/tags/v9.8.9 %s refs/tags/v9.8.9 %040d\n' "$multi_two" 0
    } | ./.githooks/pre-push origin fixture
) > "$real_hook_multi/output.log" 2>&1
multi_tag_status=$?
set -e
[ "$multi_tag_status" -ne 0 ] || fail "multiple release tags in one push were accepted"
grep -q 'push one release tag at a time' "$real_hook_multi/output.log" \
    || fail "multi-tag push rejection was not diagnosed"

make_release_fixture() {
    local fixture="$1"
    mkdir -p "$fixture/.githooks" "$fixture/scripts" "$fixture/fake-bin" "$fixture/home" "$fixture/tmp" \
        "$fixture/Casks" "$fixture/homebrew" "$fixture/docs" "$fixture/RELEASE_NOTES" \
        "$fixture/Xcode/Resources" "$fixture/Sources/MacCrabCore/Resources"
    cp "$PROJECT_DIR/.githooks/pre-push" "$fixture/.githooks/pre-push"
    cp "$SCRIPT_DIR/release.sh" "$fixture/scripts/release.sh"
    cp "$SCRIPT_DIR/release-env.sh" "$fixture/scripts/release-env.sh"
    cp "$SCRIPT_DIR/_release_env.py" "$fixture/scripts/_release_env.py"
    cp "$SCRIPT_DIR/export-release-source.py" "$fixture/scripts/export-release-source.py"

    # All files that can influence the mocked artifact are committed to a real,
    # disposable repository. The git shim delegates object/index/worktree
    # operations to /usr/bin/git and intercepts only publication, so release.sh
    # is tested against real commits, annotated tags, blob IDs, and cleanliness.
    printf '.build/\n.qualification-evidence/\n.swiftpm/\n*.log\n.fixture-*\nfail-*\nhome/\ntmp/\n' > "$fixture/.gitignore"
    printf 'private-input/\n' > "$fixture/Sources/MacCrabCore/Resources/.gitignore"
    printf 'fixture README [![Tests](https://img.shields.io/badge/tests-1%%20passing-brightgreen)]()\n' \
        > "$fixture/README.md"
    printf 'fixture coverage\n' > "$fixture/docs/COVERAGE.md"
    printf 'fixture notes\n' > "$fixture/RELEASE_NOTES/v9.9.11.md"
    printf 'fixture rc notes\n' > "$fixture/RELEASE_NOTES/v9.9.11-rc.1.md"
    printf '{}\n' > "$fixture/Xcode/Resources/MacCrabApp.entitlements"
    printf '{}\n' > "$fixture/Xcode/Resources/MacCrabAgent.entitlements"
    printf '{"version":"9.9.10","sha256":"%064d"}\n' 0 > "$fixture/release.json"
    printf 'cask "maccrab" do\n  version "9.9.10"\n  sha256 "%064d"\nend\n' 0 \
        > "$fixture/Casks/maccrab.rb"
    cp "$fixture/Casks/maccrab.rb" "$fixture/homebrew/maccrab.rb"

    write_executable "$fixture/scripts/ci-local.sh" \
        '#!/bin/bash' \
        'if env | grep -qE "^(DEVELOPER_ID|APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE|GH_TOKEN|GITHUB_TOKEN|SITE_REPO_TOKEN|TAP_REPO_TOKEN)="; then' \
        '    env | grep -E "^(DEVELOPER_ID|APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE|GH_TOKEN|GITHUB_TOKEN|SITE_REPO_TOKEN|TAP_REPO_TOKEN)=" >> "${MACCRAB_TEST_SECRET_LOG:-secret.log}"' \
        '    exit 86' \
        'fi' \
        'printf "%s\n" "$*" >> "${MACCRAB_TEST_CI_LOG:-ci.log}"' \
        'exit 0'
    write_executable "$fixture/fake-bin/gh" \
        '#!/bin/bash' \
        'printf "gh invocation: %s\n" "$*" >> "$MACCRAB_TEST_GH_LOG"' \
        'if [ -n "${GH_REPO:-}" ] || [ -n "${GH_HOST:-}" ]; then echo "hostile gh routing env survived" >> "$MACCRAB_TEST_GH_LOG"; exit 85; fi' \
        'if env | grep -qE "^(DEVELOPER_ID|APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE|SITE_REPO_TOKEN|TAP_REPO_TOKEN)="; then exit 86; fi' \
        'digest_file=${MACCRAB_TEST_REMOTE_DIGEST_FILE:-.fixture-remote-digest}' \
        'id_file=.fixture-release-id; name_file=.fixture-release-name; draft_file=.fixture-release-draft' \
        'prerelease_file=.fixture-release-prerelease; tag_file=.fixture-release-tag; url_file=.fixture-release-url' \
        'release_exists() { [ -s "$id_file" ] || [ -s "$digest_file" ]; }' \
        'clear_release() { rm -f "$id_file" "$name_file" "$draft_file" "$prerelease_file" "$tag_file" "$url_file" "$digest_file"; }' \
        'endpoint=; canonical_host=0; canonical_repo=0; previous=' \
        'for argument in "$@"; do' \
        '    if [ "$previous" = "--hostname" ] && [ "$argument" = "github.com" ]; then canonical_host=1; fi' \
        '    if [ "$previous" = "--repo" ] && [ "$argument" = "peterhanily/maccrab" ]; then canonical_repo=1; fi' \
        '    previous=$argument' \
        'done' \
        'for argument in "$@"; do case "$argument" in user|repos/*) endpoint=$argument ;; esac; done' \
        'if [ "${1:-}" = "api" ]; then' \
        '    [ "$canonical_host" = "1" ] || exit 94' \
        '    case "$endpoint" in user|repos/peterhanily/maccrab|repos/peterhanily/maccrab/*) ;; *) exit 95 ;; esac' \
        '    if [ "${MACCRAB_TEST_GH_PREFLIGHT_STATUS:-0}" != "0" ]; then exit "$MACCRAB_TEST_GH_PREFLIGHT_STATUS"; fi' \
        '    case "$endpoint" in' \
        '        user) printf "{\"login\":\"fixture\"}\n" ;;' \
        '        repos/peterhanily/maccrab/releases/tags/*)' \
        '            if [ "${MACCRAB_TEST_RELEASE_PROBE_ERROR:-0}" = "1" ]; then printf "network unavailable\n"; exit 2; fi' \
        '            if release_exists; then printf "HTTP/2.0 200 OK\n"; exit 0; fi' \
        '            printf "HTTP/2.0 404 Not Found\n"; exit 1 ;;' \
        '        repos/peterhanily/maccrab/releases/*)' \
        '            release_id=${endpoint##*/}' \
        '            if ! release_exists || { [ -s "$id_file" ] && [ "$(cat "$id_file")" != "$release_id" ]; }; then printf "HTTP/2.0 404 Not Found\n"; exit 1; fi' \
        '            case " $* " in' \
        '                *" -X DELETE "*|*" --method DELETE "*)' \
        '                    printf "unexpected-delete\n" >> "$MACCRAB_TEST_GH_LOG"; exit 98 ;;' \
        '                *" -X PATCH "*)' \
        '                    final_name=' \
        '                    final_prerelease=false' \
        '                    previous=' \
        '                    for argument in "$@"; do' \
        '                        if [ "$previous" = "-f" ] && [[ "$argument" == name=* ]]; then final_name=${argument#name=}; fi' \
        '                        if [ "$previous" = "-F" ] && [[ "$argument" == prerelease=* ]]; then final_prerelease=${argument#prerelease=}; fi' \
        '                        previous=$argument' \
        '                    done' \
        '                    if [ "${MACCRAB_TEST_PUBLISH_STAYS_DRAFT:-0}" != "1" ]; then' \
        '                        if [ "${MACCRAB_TEST_PATCH_WRONG_PUBLISHED:-0}" = "1" ]; then printf "Unexpected title\n" > "$name_file"; else printf "%s\n" "$final_name" > "$name_file"; fi' \
        '                        printf "false\n" > "$draft_file"' \
        '                        printf "%s\n" "$final_prerelease" > "$prerelease_file"' \
        '                    fi' \
        '                    [ "${MACCRAB_TEST_PATCH_STATUS:-0}" = "0" ] || exit "$MACCRAB_TEST_PATCH_STATUS"' \
        '                    case "${MACCRAB_TEST_POST_PATCH_LIVE_ATTACK:-none}" in' \
        '                        delete) rm -f .build/MacCrab-v*.dmg ;;' \
        '                        mutate) printf "post-patch-live-mutation\n" > .build/MacCrab-v*.dmg ;;' \
        '                    esac' \
        '                    exit 0 ;;' \
        '            esac' \
        '            case " $* " in' \
        '                *".assets[]"*)' \
        '                    sha=${MACCRAB_TEST_REMOTE_DIGEST_OVERRIDE:-}' \
        '                    if [ -s "$draft_file" ] && [ "$(cat "$draft_file")" = "false" ] && [ -n "${MACCRAB_TEST_POST_PUBLISH_DIGEST_OVERRIDE:-}" ]; then sha=$MACCRAB_TEST_POST_PUBLISH_DIGEST_OVERRIDE; fi' \
        '                    [ -n "$sha" ] || sha=$(cat "$digest_file")' \
        '                    printf "sha256:%s\n" "$sha" ;;' \
        '                *)' \
        '                    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$(cat "$id_file")" "$(cat "$name_file")" "$(cat "$draft_file")" "$(cat "$prerelease_file")" "$(cat "$tag_file")" "$(cat "$url_file")" ;;' \
        '            esac ;;' \
        '        repos/peterhanily/maccrab) printf "%s\n" "${MACCRAB_TEST_GH_PUSH_PERMISSION:-true}" ;;' \
        '    esac' \
        '    exit 0' \
        'fi' \
        'if [ "${1:-}" = "release" ] && [ "${2:-}" = "create" ]; then' \
        '    [ "$canonical_repo" = "1" ] || exit 96' \
        '    has_draft=0; has_verify_tag=0' \
        '    for argument in "$@"; do case "$argument" in --draft) has_draft=1 ;; --verify-tag) has_verify_tag=1 ;; esac; done' \
        '    [ "$has_draft" = "1" ] && [ "$has_verify_tag" = "1" ] || exit 88' \
        '    release_tag=; asset=' \
        '    for argument in "$@"; do case "$argument" in v[0-9]*.*) release_tag=$argument ;; */MacCrab-v*.dmg) asset=$argument ;; esac; done' \
        '    [ -n "$release_tag" ] && [ -n "$asset" ] || exit 89' \
        '    title=' \
        '    previous=' \
        '    for argument in "$@"; do if [ "$previous" = "--title" ]; then title=$argument; fi; previous=$argument; done' \
        '    if [ "${MACCRAB_TEST_CONCURRENT_RELEASE:-0}" = "1" ]; then' \
        '        printf "5252\n" > "$id_file"; printf "Concurrent owner\n" > "$name_file"; printf "true\n" > "$draft_file"' \
        '        printf "false\n" > "$prerelease_file"; printf "%s\n" "$release_tag" > "$tag_file"; printf "https://fixture.invalid/concurrent\n" > "$url_file"' \
        '        exit 71' \
        '    fi' \
        '    upload_sha=$(shasum -a 256 "$asset" | cut -c1-64)' \
        '    printf "4242\n" > "$id_file"; printf "%s\n" "$title" > "$name_file"; printf "true\n" > "$draft_file"' \
        '    case " $* " in *" --prerelease "*) printf "true\n" > "$prerelease_file" ;; *) printf "false\n" > "$prerelease_file" ;; esac' \
        '    printf "%s\n" "$release_tag" > "$tag_file"; printf "https://fixture.invalid/releases/%s\n" "$release_tag" > "$url_file"' \
        '    if [ "${MACCRAB_TEST_UPLOAD_SWAP:-0}" = "1" ]; then' \
        '        for original in .build/MacCrab-v*.dmg; do' \
        '            [ -f "$original" ] || continue' \
        '            printf "attacker-path-swap\n" > "$original"' \
        '            /bin/cp "$asset" "$original"' \
        '            break' \
        '        done' \
        '    fi' \
        '    printf "%s\n" "$upload_sha" > "$digest_file"' \
        '    if [ "${MACCRAB_TEST_GH_STATUS:-0}" != "0" ]; then' \
        '        if [ "${MACCRAB_TEST_PARTIAL_GH_CREATE:-0}" != "1" ]; then clear_release; fi' \
        '        exit "${MACCRAB_TEST_GH_STATUS:-0}"' \
        '    fi' \
        '    exit 0' \
        'fi' \
        'if [ "${1:-}" = "release" ] && [ "${2:-}" = "view" ]; then' \
        '    [ "$canonical_repo" = "1" ] || exit 96' \
        '    release_exists || exit 1' \
        '    printf "%s\t%s\t%s\n" "$(cat "$id_file")" "$(cat "$name_file")" "$(cat "$draft_file")"' \
        '    exit 0' \
        'fi' \
        'if [ "${1:-}" = "release" ] && [ "${2:-}" = "delete" ]; then printf "unexpected-delete\n" >> "$MACCRAB_TEST_GH_LOG"; exit 97; fi' \
        'exit 99'
    write_executable "$fixture/fake-bin/git" \
        '#!/bin/bash' \
        'case "${1:-}" in' \
        '    credential) exit 1 ;;' \
        '    rev-parse)' \
        '        if [ "${2:-}" = "--git-path" ] && [ -n "${MACCRAB_TEST_HOOK_PATH:-}" ]; then printf "%s\n" "$MACCRAB_TEST_HOOK_PATH"; exit 0; fi' \
        '        exec /usr/bin/git "$@" ;;' \
        '    ls-remote)' \
        '        want=""' \
        '        for arg in "$@"; do case "$arg" in refs/*) want=$arg ;; esac; done' \
        '        case "$want" in' \
        '            refs/heads/*)' \
        '                [ -s .fixture-remote-branch-commit ] || exit 0' \
        '                printf "%s\t%s\n" "$(cat .fixture-remote-branch-commit)" "$want" ;;' \
        '            *)' \
        '                [ -s .fixture-remote-tag-object ] || exit 0' \
        '                printf "%s\t%s\n" "$(cat .fixture-remote-tag-object)" "$(cat .fixture-remote-tag-name 2>/dev/null || printf "%s" "$want")" ;;' \
        '        esac ;;' \
        '    push)' \
        '        case "$*" in' \
        '            *refs/tags/*)' \
        '                tag_ref=${!#}; tag_ref=${tag_ref#refs/tags/}; tag_ref=${tag_ref#*:refs/tags/}' \
        '                tag_object=$(/usr/bin/git rev-parse "refs/tags/$tag_ref")' \
        '                if [ -n "${MACCRAB_TEST_GIT_LOG:-}" ]; then printf "expected=%s sha=%s commit=%s tag=%s hook=%s source=%s source_tree=%s metadata_tree=%s\n" "${MACCRAB_RELEASE_EXPECTED_DMG:-}" "${MACCRAB_RELEASE_EXPECTED_SHA256:-}" "${MACCRAB_RELEASE_EXPECTED_COMMIT:-}" "${MACCRAB_RELEASE_EXPECTED_TAG_OBJECT:-}" "${MACCRAB_RELEASE_EXPECTED_HOOK_BLOB:-}" "${MACCRAB_RELEASE_SOURCE_COMMIT:-}" "${MACCRAB_RELEASE_SOURCE_TREE:-}" "${MACCRAB_RELEASE_METADATA_TREE:-}" >> "$MACCRAB_TEST_GIT_LOG"; fi' \
        '                printf "refs/tags/%s %s refs/tags/%s %040d\n" "$tag_ref" "$tag_object" "$tag_ref" 0 | ./.githooks/pre-push origin fixture' \
        '                printf "%s\n" "$tag_object" > .fixture-remote-tag-object' \
        '                printf "refs/tags/%s\n" "$tag_ref" > .fixture-remote-tag-name' \
        '                case "${MACCRAB_TEST_ARTIFACT_ATTACK:-none}" in' \
        '                    delete) rm -f .build/MacCrab-v*.dmg ;;' \
        '                    zero) : > .build/MacCrab-v*.dmg ;;' \
        '                    mutate) printf "attacker-replaced-bytes\n" > .build/MacCrab-v*.dmg ;;' \
        '                esac ;;' \
        '            *)' \
        '                head=$(/usr/bin/git rev-parse HEAD)' \
        '                printf "refs/heads/main %s refs/heads/main %040d\n" "$head" 0 | ./.githooks/pre-push origin fixture' \
        '                printf "%s\n" "$head" > .fixture-remote-branch-commit' \
        '                if [ "${MACCRAB_TEST_MUTATE_ORIGIN_AFTER_BRANCH:-0}" = "1" ]; then /usr/bin/git remote set-url origin https://github.com/attacker/maccrab.git; fi ;;' \
        '        esac ;;' \
        '    *) exec /usr/bin/git "$@" ;;' \
        'esac'

    write_executable "$fixture/scripts/pre-release-audit.sh" '#!/bin/bash' 'exit 0'
    write_executable "$fixture/scripts/prepare-release-pyyaml.sh" \
        '#!/bin/bash' 'exit 0'
    write_executable "$fixture/scripts/run-release-python.sh" \
        '#!/bin/bash' \
        'case "$*" in' \
        '    *compile_rules.py*) printf "Rules compiled: 1\nRules skipped: 0\n" ;;' \
        'esac' \
        'exit 0'
    printf '%s\n' 'print("fixture coverage")' \
        > "$fixture/scripts/generate-coverage-doc.py"
    write_executable "$fixture/scripts/generate-appcast-entry.sh" \
        '#!/bin/bash' \
        'if env | grep -qE "^(DEVELOPER_ID|APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE|GH_TOKEN|GITHUB_TOKEN|SITE_REPO_TOKEN|TAP_REPO_TOKEN)="; then exit 86; fi' \
        'fixture_root=__FIXTURE_ROOT__' \
        'dmg=; previous=' \
        'for argument in "$@"; do if [ "$previous" = "--dmg" ]; then dmg=$argument; fi; previous=$argument; done' \
        '[ -f "$dmg" ] && [ ! -L "$dmg" ] && [ -s "$dmg" ] || exit 88' \
        'snapshot_sha=$(/usr/bin/shasum -a 256 "$dmg" | /usr/bin/awk '\''{print $1}'\'')' \
        '[ "$snapshot_sha" = "$(cat "$fixture_root/.fixture-remote-digest")" ] || exit 89' \
        'printf "%s\n" "$dmg" > "$fixture_root/snapshot.path"' \
        'printf "appcast-generate\n" >> "${MACCRAB_TEST_PUBLISH_LOG:-$fixture_root/publish.log}"' \
        '[ ! -f "$fixture_root/fail-appcast-generate" ] || exit 1' \
        'printf "<item/>\n"' \
        'exit 0'
    write_executable "$fixture/scripts/publish-appcast-entry.sh" \
        '#!/bin/bash' \
        'if env | grep -qE "^(DEVELOPER_ID|APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE|GH_TOKEN|GITHUB_TOKEN|TAP_REPO_TOKEN)="; then exit 86; fi' \
        '[ -n "${SITE_REPO_TOKEN:-}" ] || exit 87' \
        'fixture_root=__FIXTURE_ROOT__; snapshot=$(cat "$fixture_root/snapshot.path"); [ -s "$snapshot" ] || exit 88' \
        'printf "appcast-publish\n" >> "${MACCRAB_TEST_PUBLISH_LOG:-$fixture_root/publish.log}"' \
        '[ ! -f "$fixture_root/fail-appcast-publish" ] || exit 1' \
        'exit 0'
    write_executable "$fixture/scripts/publish-release-json.sh" \
        '#!/bin/bash' \
        'if env | grep -qE "^(DEVELOPER_ID|APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE|GH_TOKEN|GITHUB_TOKEN|TAP_REPO_TOKEN)="; then exit 86; fi' \
        '[ -n "${SITE_REPO_TOKEN:-}" ] || exit 87' \
        'fixture_root=__FIXTURE_ROOT__; [ -s "$(cat "$fixture_root/snapshot.path" 2>/dev/null || true)" ] || [ "${SKIP_APPCAST:-0}" = "1" ] || exit 88' \
        'if [ -n "${MACCRAB_TEST_PUBLISH_LOG:-}" ]; then printf "release-json\n" >> "$MACCRAB_TEST_PUBLISH_LOG"; fi' \
        'exit "${MACCRAB_TEST_RELEASE_JSON_STATUS:-0}"'
    write_executable "$fixture/scripts/publish-cask.sh" \
        '#!/bin/bash' \
        'if env | grep -qE "^(DEVELOPER_ID|APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE|GH_TOKEN|GITHUB_TOKEN|SITE_REPO_TOKEN)="; then exit 86; fi' \
        '[ -n "${TAP_REPO_TOKEN:-}" ] || exit 87' \
        'fixture_root=__FIXTURE_ROOT__; [ -s "$(cat "$fixture_root/snapshot.path" 2>/dev/null || true)" ] || [ "${SKIP_APPCAST:-0}" = "1" ] || exit 88' \
        'if [ -n "${MACCRAB_TEST_PUBLISH_LOG:-}" ]; then printf "cask\n" >> "$MACCRAB_TEST_PUBLISH_LOG"; fi' \
        'exit "${MACCRAB_TEST_CASK_PUBLISH_STATUS:-0}"'
    write_executable "$fixture/fake-bin/curl" \
        '#!/bin/bash' \
        'cat release.json'
    # release.sh deliberately waits between remote-state retries in production.
    # These disposable fixtures provide every remote transition synchronously,
    # so real 2s/10s sleeps add minutes without exercising another state. Keep
    # the retry loops and assertions intact while making fixture time bounded.
    write_executable "$fixture/fake-bin/sleep" \
        '#!/bin/bash' \
        'exit 0'
    write_executable "$fixture/scripts/build-release.sh" \
        '#!/bin/bash' \
        'set -euo pipefail' \
        'stage=${1:-all}' \
        'fixture_root=$(dirname "$MACCRAB_TEST_GH_LOG")' \
        'build_log=${MACCRAB_TEST_BUILD_LOG:-$fixture_root/build.log}' \
        'printf "%s\n" "$stage" >> "$build_log"' \
        'printf "%s\n" "$PWD" >> "$fixture_root/build-pwd.log"' \
        '[[ "$PWD" == /private/tmp/maccrab-release-build.* ]] || exit 80' \
        '[ ! -e .git ] && [ ! -e .swiftpm ] || exit 81' \
        '[ ! -e Sources/MacCrabCore/Resources/private-input/poison.yml ] || exit 82' \
        '[ "${MACCRAB_TRACKED_EXPORT:-0}" = "1" ] || exit 83' \
        '[[ "${MACCRAB_RELEASE_SOURCE_COMMIT:-}" =~ ^[0-9a-f]{40,64}$ ]] || exit 84' \
        '[[ "${MACCRAB_RELEASE_SOURCE_TREE:-}" =~ ^[0-9a-f]{40,64}$ ]] || exit 85' \
        'case "$stage" in' \
        '    unsigned-build|assemble)' \
        '        if env | grep -qE "^(DEVELOPER_ID|APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE|GH_TOKEN|GITHUB_TOKEN|SITE_REPO_TOKEN|TAP_REPO_TOKEN)="; then exit 86; fi ;;' \
        '    sign)' \
        '        if env | grep -qE "^(APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE|GH_TOKEN|GITHUB_TOKEN|SITE_REPO_TOKEN|TAP_REPO_TOKEN)="; then exit 86; fi' \
        '        [ -n "${DEVELOPER_ID:-}" ] || exit 87 ;;' \
        '    publish)' \
        '        if env | grep -qE "^(GH_TOKEN|GITHUB_TOKEN|SITE_REPO_TOKEN|TAP_REPO_TOKEN)="; then exit 86; fi' \
        '        mkdir -p .build Casks homebrew' \
        '        dmg=".build/MacCrab-v$VERSION.dmg"' \
        '        if [ "${MACCRAB_TEST_BUILD_ZERO_DMG:-0}" = "1" ]; then : > "$dmg"; else printf "signed-notarized-stapled-release\n" > "$dmg"; fi' \
        '        printf "notary_submission_id=12345678-1234-4123-8123-123456789abc\n" > "$dmg.notary-submission-id"' \
        '        sha=$(shasum -a 256 "$dmg" | awk '\''{print $1}'\'')' \
        '        case "$VERSION" in' \
        '            *-rc.*) ;;' \
        '            *)' \
        '                printf '\''{"version":"%s","sha256":"%s"}\n'\'' "$VERSION" "$sha" > release.json' \
        '                printf '\''cask "maccrab" do\n  version "%s"\n  sha256 "%s"\nend\n'\'' "$VERSION" "$sha" > Casks/maccrab.rb' \
        '                cp Casks/maccrab.rb homebrew/maccrab.rb ;;' \
        '        esac ;;' \
        'esac'

    # Python stub for the copied release flow. It models the gate boundary and
    # lets individual fixtures force a qualification failure; the real verifier
    # has its own deterministic threshold/mutation suite.
    printf '%s\n' \
        'import hashlib, json, os, pathlib, sys' \
        'args = sys.argv[1:]' \
        'command = args[0] if args else ""' \
        'def value(flag): return args[args.index(flag) + 1]' \
        'if command == "verify-release":' \
        '    if os.environ.get("MACCRAB_TEST_QUALIFICATION_FAIL") == "1": print("fixture qualification mismatch", file=sys.stderr); raise SystemExit(74)' \
        '    for flag in ("--dmg", "--candidate-manifest", "--runtime-report", "--containment-report"):' \
        '        path = pathlib.Path(value(flag)); assert path.is_file() and path.stat().st_size > 0' \
        'elif command in ("record-candidate", "runtime-template"):' \
        '    path = pathlib.Path(value("--output")); path.parent.mkdir(parents=True, exist_ok=True); path.write_text("{}\\n")' \
        'elif command == "emit-release-json":' \
        '    version = value("--version"); dmg = pathlib.Path.cwd() / ".build" / ("MacCrab-v" + version + ".dmg")' \
        '    sha = hashlib.sha256(dmg.read_bytes()).hexdigest(); pathlib.Path(value("--output")).write_text(json.dumps({"version": version, "sha256": sha}) + "\\n")' \
        'raise SystemExit(0)' \
        > "$fixture/scripts/candidate-qualification.py"
    /bin/chmod 0755 "$fixture/scripts/candidate-qualification.py"
    install_missing_critical_executor_fixtures "$fixture"
    write_executable "$fixture/.githooks/pre-commit" \
        '#!/bin/bash' \
        ': > .fixture-commit-hook-ran' \
        'echo "release-time porcelain commit hook executed" >&2' \
        'exit 91'
    write_executable "$fixture/.githooks/commit-msg" \
        '#!/bin/bash' \
        ': > .fixture-commit-msg-hook-ran' \
        'exit 92'
    write_executable "$fixture/.githooks/reference-transaction" \
        '#!/bin/bash' \
        'while read -r old new ref; do' \
        '    if [ "$ref" = "refs/heads/main" ]; then' \
        '        : > .fixture-reference-hook-ran' \
        '        echo "release-time reference hook executed" >&2' \
        '        exit 93' \
        '    fi' \
        'done' \
        'exit 0'

    # Pin production tool constants to absolute fixture simulators only in the
    # copied-and-committed disposable script. Production exposes no override.
    /usr/bin/sed -i '' \
        -e "s#GIT_BIN=/usr/bin/git#GIT_BIN=${fixture}/fake-bin/git#" \
        -e "s#GH_BIN=/opt/homebrew/bin/gh#GH_BIN=${fixture}/fake-bin/gh#" \
        -e "s#CURL_BIN=/usr/bin/curl#CURL_BIN=${fixture}/fake-bin/curl#" \
        -e "s#PATH=/usr/bin:/bin:/usr/sbin:/sbin#PATH=${fixture}/fake-bin:/usr/bin:/bin:/usr/sbin:/sbin#" \
        "$fixture/scripts/release.sh"
    # Production exits here unconditionally. Only this disposable, committed
    # fixture copy continues so the existing post-boundary attack simulations
    # can exercise tag/push/upload behavior without a 15-minute host run.
    /usr/bin/sed -i '' \
        's@^    exit 3 # exact-candidate-phase-boundary: fixture tests patch only their disposable copy$@    CANDIDATE_READY=1; QUALIFIED_CANDIDATE_SHA=$(shasum -a 256 "$DMG_PATH" | awk '\''{print $1}'\''); QUALIFIED_MANIFEST_SHA=$(shasum -a 256 "$CANDIDATE_MANIFEST" | awk '\''{print $1}'\''); QUALIFIED_RUNTIME_SHA=$(shasum -a 256 "$RUNTIME_REPORT" | awk '\''{print $1}'\''); QUALIFIED_CONTAINMENT_SHA=$(shasum -a 256 "$CONTAINMENT_REPORT" | awk '\''{print $1}'\'')@' \
        "$fixture/scripts/release.sh"
    /usr/bin/sed -i '' "s#__FIXTURE_ROOT__#${fixture}#g" \
        "$fixture/scripts/generate-appcast-entry.sh" \
        "$fixture/scripts/publish-appcast-entry.sh" \
        "$fixture/scripts/publish-release-json.sh" \
        "$fixture/scripts/publish-cask.sh"

    (
        cd "$fixture"
        /usr/bin/git init -q
        /usr/bin/git checkout -q -b main
        /usr/bin/git config user.name 'MacCrab release fixture'
        /usr/bin/git config user.email 'release-fixture@invalid.example'
        /usr/bin/git config user.signingkey ''
        /usr/bin/git config commit.gpgSign false
        /usr/bin/git config tag.gpgSign false
        /usr/bin/git config core.hooksPath .no-hooks
        /usr/bin/git add .
        /usr/bin/git commit -q -m 'release fixture'
        /usr/bin/git config core.hooksPath .githooks
        /usr/bin/git remote add origin https://github.com/peterhanily/maccrab.git
    )
    /bin/mkdir -p "$fixture/.swiftpm/configuration" \
        "$fixture/Sources/MacCrabCore/Resources/private-input"
    printf 'hostile mirror configuration\n' > "$fixture/.swiftpm/configuration/registries.json"
    printf 'ignored resource poison\n' \
        > "$fixture/Sources/MacCrabCore/Resources/private-input/poison.yml"
    /bin/mkdir -p "$fixture/.qualification-evidence"
    printf '{}\n' > "$fixture/.qualification-evidence/MacCrab-v9.9.11.containment.json"
    printf '{}\n' > "$fixture/.qualification-evidence/MacCrab-v9.9.11-rc.1.containment.json"
}

run_release_attack() {
    local attack="$1"
    local expected_message="$2"
    local fixture="$TEST_ROOT/release-$attack"
    make_release_fixture "$fixture"
    set +e
    (
        cd "$fixture"
        PATH="$fixture/fake-bin:/usr/bin:/bin" \
            HOME="$fixture/home" \
            TMPDIR="$fixture/tmp" \
            DEVELOPER_ID="fixture identity" \
            SITE_REPO_TOKEN="fixture token" \
            SKIP_APPCAST=1 \
            RELEASE_BRANCH=main \
            MACCRAB_TEST_ARTIFACT_ATTACK="$attack" \
            MACCRAB_TEST_GH_LOG="$fixture/gh.log" \
            ./scripts/release.sh 9.9.11 --skip-prerelease-check
    ) > "$fixture/output.log" 2>&1
    local status=$?
    set -e
    [ "$status" -ne 0 ] || fail "release.sh exited 0 after the tag push made the DMG $attack"
    grep -q "$expected_message" "$fixture/output.log" \
        || fail "release.sh did not diagnose the $attack artifact"
    ! grep -q 'MacCrab v9.9.11 Released!' "$fixture/output.log" \
        || fail "release.sh printed a success banner after the DMG was $attack"
    ! grep -q 'release create' "$fixture/gh.log" \
        || fail "release.sh invoked release creation with a $attack artifact"
}

# The release publisher is now a two-phase exact-candidate state machine. These
# focused fixtures prove that evidence failures happen before every mutation and
# that a qualified second phase reuses the preserved bytes without rebuilding.
qualification_missing="$TEST_ROOT/release-qualification-missing"
make_release_fixture "$qualification_missing"
/bin/mkdir -p "$qualification_missing/.build"
printf 'preserved candidate\n' > "$qualification_missing/.build/MacCrab-v9.9.11.dmg"
printf '{}\n' > "$qualification_missing/.qualification-evidence/MacCrab-v9.9.11.candidate.json"
set +e
(
    cd "$qualification_missing"
    PATH="$qualification_missing/fake-bin:/usr/bin:/bin" \
        HOME="$qualification_missing/home" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_GH_LOG="$qualification_missing/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$qualification_missing/output.log" 2>&1
qualification_missing_status=$?
set -e
[ "$qualification_missing_status" -ne 0 ] || fail "release accepted missing installed-host evidence"
/usr/bin/grep -q 'PUBLICATION STOPPED' "$qualification_missing/output.log" \
    || fail "missing runtime evidence did not explain the phase boundary"
[ ! -s "$qualification_missing/build.log" ] || fail "missing evidence caused a qualified candidate rebuild"
[ ! -s "$qualification_missing/gh.log" ] || fail "missing evidence reached GitHub"

qualification_mismatch="$TEST_ROOT/release-qualification-mismatch"
make_release_fixture "$qualification_mismatch"
/bin/mkdir -p "$qualification_mismatch/.build"
printf 'preserved candidate\n' > "$qualification_mismatch/.build/MacCrab-v9.9.11.dmg"
printf '{}\n' > "$qualification_mismatch/.qualification-evidence/MacCrab-v9.9.11.candidate.json"
printf '{}\n' > "$qualification_mismatch/.qualification-evidence/MacCrab-v9.9.11.runtime.json"
set +e
(
    cd "$qualification_mismatch"
    PATH="$qualification_mismatch/fake-bin:/usr/bin:/bin" \
        HOME="$qualification_mismatch/home" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_QUALIFICATION_FAIL=1 \
        MACCRAB_TEST_GH_LOG="$qualification_mismatch/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$qualification_mismatch/output.log" 2>&1
qualification_mismatch_status=$?
set -e
[ "$qualification_mismatch_status" -ne 0 ] || fail "release accepted mismatched candidate evidence"
/usr/bin/grep -q 'candidate qualification failed' "$qualification_mismatch/output.log" \
    || fail "mismatched candidate evidence was not diagnosed"
[ ! -s "$qualification_mismatch/build.log" ] || fail "mismatched evidence caused a candidate rebuild"
[ ! -s "$qualification_mismatch/gh.log" ] || fail "mismatched evidence reached GitHub"

qualified_reuse="$TEST_ROOT/release-qualified-reuse"
make_release_fixture "$qualified_reuse"
/bin/mkdir -p "$qualified_reuse/.build"
printf 'preserved candidate\n' > "$qualified_reuse/.build/MacCrab-v9.9.11-rc.1.dmg"
printf '{}\n' > "$qualified_reuse/.qualification-evidence/MacCrab-v9.9.11-rc.1.candidate.json"
printf '{}\n' > "$qualified_reuse/.qualification-evidence/MacCrab-v9.9.11-rc.1.runtime.json"
(
    cd "$qualified_reuse"
    PATH="$qualified_reuse/fake-bin:/usr/bin:/bin" \
        HOME="$qualified_reuse/home" \
        TMPDIR="$qualified_reuse/tmp" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_GH_LOG="$qualified_reuse/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$qualified_reuse/publish.log" \
        ./scripts/release.sh 9.9.11-rc.1 --skip-prerelease-check --publish-rc
) > "$qualified_reuse/output.log" 2>&1 \
    || fail "qualified second phase did not publish the preserved RC fixture"
[ ! -s "$qualified_reuse/build.log" ] || fail "qualified second phase rebuilt the installed-host-tested candidate"
/usr/bin/grep -q 'Reusing exact installed-host-qualified candidate' "$qualified_reuse/output.log" \
    || fail "qualified second phase did not report preserved-candidate reuse"
/usr/bin/grep -q 'release create' "$qualified_reuse/gh.log" \
    || fail "qualified second phase did not reach the isolated RC publisher"

# Artifact construction starts only from a fully committed source snapshot, and
# every entitlement used by codesign must be represented by that commit.
release_untracked="$TEST_ROOT/release-untracked-input"
make_release_fixture "$release_untracked"
printf 'untracked build input\n' > "$release_untracked/Untracked.swift"
set +e
(
    cd "$release_untracked"
    PATH="$release_untracked/fake-bin:/usr/bin:/bin" \
        HOME="$release_untracked/home" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        MACCRAB_TEST_GH_LOG="$release_untracked/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_untracked/output.log" 2>&1
release_untracked_status=$?
set -e
[ "$release_untracked_status" -ne 0 ] || fail "release accepted an untracked Swift build input"
grep -q 'release source is not clean' "$release_untracked/output.log" \
    || fail "untracked release input was not diagnosed before build"
[ ! -s "$release_untracked/build.log" ] || fail "release built from an untracked source snapshot"

for hidden_mode in assume-unchanged skip-worktree both; do
    release_hidden="$TEST_ROOT/release-hidden-${hidden_mode}"
    make_release_fixture "$release_hidden"
    case "$hidden_mode" in
        assume-unchanged)
            /usr/bin/git -C "$release_hidden" update-index --assume-unchanged scripts/build-release.sh ;;
        skip-worktree)
            /usr/bin/git -C "$release_hidden" update-index --skip-worktree scripts/build-release.sh ;;
        both)
            /usr/bin/git -C "$release_hidden" update-index --assume-unchanged scripts/build-release.sh
            /usr/bin/git -C "$release_hidden" update-index --skip-worktree scripts/build-release.sh ;;
    esac
    printf '\n# hidden release executor mutation\n' >> "$release_hidden/scripts/build-release.sh"
    [ -z "$(/usr/bin/git -C "$release_hidden" status --porcelain)" ] \
        || fail "$hidden_mode release fixture was visible to git status"
    set +e
    (
        cd "$release_hidden"
        HOME="$release_hidden/home" DEVELOPER_ID="fixture identity" \
            SITE_REPO_TOKEN="fixture token" \
            MACCRAB_TEST_GH_LOG="$release_hidden/gh.log" \
            ./scripts/release.sh 9.9.11 --skip-prerelease-check
    ) > "$release_hidden/output.log" 2>&1
    release_hidden_status=$?
    set -e
    [ "$release_hidden_status" -ne 0 ] \
        || fail "release accepted $hidden_mode critical-executor mutation"
    /usr/bin/grep -q 'assume-unchanged/skip-worktree' "$release_hidden/output.log" \
        || fail "release did not diagnose $hidden_mode index state"
    [ ! -s "$release_hidden/build.log" ] \
        || fail "release built after $hidden_mode executor mutation"
done

release_tracked_swiftpm="$TEST_ROOT/release-tracked-swiftpm-config"
make_release_fixture "$release_tracked_swiftpm"
/usr/bin/git -C "$release_tracked_swiftpm" add -f .swiftpm/configuration/registries.json
/usr/bin/git -C "$release_tracked_swiftpm" -c core.hooksPath=.no-hooks \
    commit -q -m 'track hostile SwiftPM configuration fixture'
set +e
(
    cd "$release_tracked_swiftpm"
    HOME="$release_tracked_swiftpm/home" DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        MACCRAB_TEST_GH_LOG="$release_tracked_swiftpm/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_tracked_swiftpm/output.log" 2>&1
tracked_swiftpm_status=$?
set -e
[ "$tracked_swiftpm_status" -ne 0 ] || fail "release accepted tracked .swiftpm configuration"
/usr/bin/grep -q 'SwiftPM configuration must not be a release input' \
        "$release_tracked_swiftpm/output.log" \
    || fail "tracked .swiftpm configuration was not diagnosed"
[ ! -s "$release_tracked_swiftpm/build.log" ] \
    || fail "release built with tracked .swiftpm configuration"

release_missing_entitlement="$TEST_ROOT/release-missing-tracked-entitlement"
make_release_fixture "$release_missing_entitlement"
/usr/bin/git -C "$release_missing_entitlement" rm -q Xcode/Resources/MacCrabAgent.entitlements
/usr/bin/git -C "$release_missing_entitlement" -c core.hooksPath=.no-hooks \
    commit -q -m 'remove entitlement fixture'
set +e
(
    cd "$release_missing_entitlement"
    PATH="$release_missing_entitlement/fake-bin:/usr/bin:/bin" \
        HOME="$release_missing_entitlement/home" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        MACCRAB_TEST_GH_LOG="$release_missing_entitlement/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_missing_entitlement/output.log" 2>&1
release_missing_entitlement_status=$?
set -e
[ "$release_missing_entitlement_status" -ne 0 ] \
    || fail "release accepted a source commit missing a shipped entitlement manifest"
grep -q 'shipped signing capability is not tracked' "$release_missing_entitlement/output.log" \
    || fail "missing tracked entitlement was not diagnosed before build"
[ ! -s "$release_missing_entitlement/build.log" ] \
    || fail "release built without a committed agent entitlement"

# A release from a fresh/misconfigured clone must not merely assume Git will
# execute the versioned gate. Abort before the mocked build creates `.build`.
hook_unconfigured="$TEST_ROOT/release-hook-unconfigured"
make_release_fixture "$hook_unconfigured"
set +e
(
    cd "$hook_unconfigured"
    PATH="$hook_unconfigured/fake-bin:/usr/bin:/bin" \
        HOME="$hook_unconfigured/home" \
        DEVELOPER_ID="fixture identity" \
        APPLE_ID="fixture@example.invalid" \
        APPLE_TEAM_ID="ABCDEFGHIJ" \
        NOTARIZE_PASSWORD="fixture-notary-password" \
        NOTARIZE_KEYCHAIN_PROFILE="fixture-profile" \
        GH_TOKEN="fixture-gh-token" \
        SITE_REPO_TOKEN="fixture token" \
        TAP_REPO_TOKEN="fixture-tap-token" \
        MACCRAB_TEST_HOOK_PATH=.git/hooks/pre-push \
        MACCRAB_TEST_GH_LOG="$hook_unconfigured/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$hook_unconfigured/output.log" 2>&1
hook_unconfigured_status=$?
set -e
[ "$hook_unconfigured_status" -ne 0 ] || fail "release.sh accepted an unconfigured versioned pre-push gate"
grep -q 'versioned pre-push release gate is not configured/executable' "$hook_unconfigured/output.log" \
    || fail "release.sh did not diagnose the unconfigured pre-push gate"
[ ! -d "$hook_unconfigured/.build" ] \
    || fail "release.sh started building before validating the configured hook"

# Configuration alone is insufficient if the checked-in gate lost its execute
# bit (for example in a malformed archive or manual copy).
hook_nonexecutable="$TEST_ROOT/release-hook-nonexecutable"
make_release_fixture "$hook_nonexecutable"
chmod -x "$hook_nonexecutable/.githooks/pre-push"
set +e
(
    cd "$hook_nonexecutable"
    PATH="$hook_nonexecutable/fake-bin:/usr/bin:/bin" \
        HOME="$hook_nonexecutable/home" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        MACCRAB_TEST_GH_LOG="$hook_nonexecutable/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$hook_nonexecutable/output.log" 2>&1
hook_nonexecutable_status=$?
set -e
[ "$hook_nonexecutable_status" -ne 0 ] || fail "release.sh accepted a non-executable versioned pre-push gate"
grep -qE 'versioned pre-push release gate is not configured/executable|release index/worktree differs from HEAD' \
        "$hook_nonexecutable/output.log" \
    || fail "release.sh did not diagnose the non-executable/changed pre-push gate"
[ ! -d "$hook_nonexecutable/.build" ] \
    || fail "release.sh built before checking the versioned gate's execute bit"

# A zero-byte build has a valid SHA-256 and can be reflected consistently into
# release.json/casks. Reject it as an artifact before any tag or upload work.
release_zero_build="$TEST_ROOT/release-zero-build"
make_release_fixture "$release_zero_build"
set +e
(
    cd "$release_zero_build"
    PATH="$release_zero_build/fake-bin:/usr/bin:/bin" \
        HOME="$release_zero_build/home" \
        TMPDIR="$release_zero_build/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_BUILD_ZERO_DMG=1 \
        MACCRAB_TEST_GH_STATUS=0 \
        MACCRAB_TEST_GH_LOG="$release_zero_build/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_zero_build/output.log" 2>&1
release_zero_build_status=$?
set -e
[ "$release_zero_build_status" -ne 0 ] || fail "release.sh accepted a zero-byte built DMG"
grep -q 'build did not produce a non-empty regular release DMG' "$release_zero_build/output.log" \
    || fail "release.sh did not diagnose the zero-byte built DMG"
! grep -q 'release create' "$release_zero_build/gh.log" \
    || fail "release.sh uploaded a zero-byte built DMG"

# Happy path: with no artifact attack, the same disposable release fixture must
# reach gh with the exact expected DMG path and only then print its success
# banner. This catches a guard that protects the file but accidentally prevents
# every release from completing.
release_ok="$TEST_ROOT/release-success"
make_release_fixture "$release_ok"
release_ok_source=$(/usr/bin/git -C "$release_ok" rev-parse HEAD)
release_ok_source_tree=$(/usr/bin/git -C "$release_ok" rev-parse "$release_ok_source^{tree}")
(
    cd "$release_ok"
    PATH="$release_ok/fake-bin:/usr/bin:/bin" \
        HOME="$release_ok/home" \
        TMPDIR="$release_ok/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        GH_REPO=attacker/redirected GH_HOST=evil.invalid \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_ARTIFACT_ATTACK=none \
        MACCRAB_TEST_GH_STATUS=0 \
        MACCRAB_TEST_GH_LOG="$release_ok/gh.log" \
        MACCRAB_TEST_GIT_LOG="$release_ok/git.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_ok/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_ok/output.log" 2>&1 \
    || {
        tail -60 "$release_ok/output.log" >&2
        fail "release.sh rejected an unchanged post-push DMG"
    }
grep -qE 'release create --repo peterhanily/maccrab v9\.9\.11 /private/tmp/maccrab-release-upload\.[^/]*/MacCrab-v9\.9\.11\.dmg' \
        "$release_ok/gh.log" \
    || fail "release.sh did not upload through a private snapshot"
! grep -q 'release create v9.9.11 .build/MacCrab-v9.9.11.dmg' "$release_ok/gh.log" \
    || fail "release.sh reopened the attacker-influenced .build pathname for upload"
grep -q 'expected=.build/MacCrab-v9.9.11.dmg sha=[a-f0-9]\{64\}' "$release_ok/git.log" \
    || fail "release.sh did not bind the tag hook to the pre-tag DMG manifest"
grep -qE 'commit=[a-f0-9]{40,64} tag=[a-f0-9]{40,64} hook=[a-f0-9]{40,64} source=[a-f0-9]{40,64} source_tree=[a-f0-9]{40,64} metadata_tree=[a-f0-9]{40,64}' "$release_ok/git.log" \
    || fail "release.sh omitted commit/tag/source/tree binding from the tag manifest"
release_ok_final=$(/usr/bin/git -C "$release_ok" rev-parse HEAD)
release_ok_metadata_tree=$(/usr/bin/git -C "$release_ok" rev-parse "$release_ok_final^{tree}")
[ "$(/usr/bin/git -C "$release_ok" rev-list --parents -n 1 "$release_ok_final")" \
        = "$release_ok_final $release_ok_source" ] \
    || fail "GA metadata commit is not the exact captured source's single child"
[ "$(/usr/bin/git -C "$release_ok" rev-parse "$release_ok_source^{tree}")" \
        = "$release_ok_source_tree" ] \
    || fail "captured source tree changed during release"
[ "$(/usr/bin/git -C "$release_ok" diff-tree --no-commit-id --name-only -r \
        "$release_ok_source" "$release_ok_final" | LC_ALL=C /usr/bin/sort)" \
        = $'Casks/maccrab.rb\nhomebrew/maccrab.rb\nrelease.json' ] \
    || fail "GA metadata commit changed paths outside the exact allowlist"
for metadata_path in release.json Casks/maccrab.rb homebrew/maccrab.rb; do
    [ "$(/usr/bin/git -C "$release_ok" rev-parse "$release_ok_final:$metadata_path")" \
            = "$(/usr/bin/git -C "$release_ok" hash-object --no-filters "$release_ok/$metadata_path")" ] \
        || fail "final metadata blob does not match live generated bytes: $metadata_path"
done
[ "$(/usr/bin/git -C "$release_ok" rev-parse 'v9.9.11^{commit}')" = "$release_ok_final" ] \
    || fail "release tag does not peel to the exact final metadata commit"
/usr/bin/grep -q "source=$release_ok_source source_tree=$release_ok_source_tree metadata_tree=$release_ok_metadata_tree" \
        "$release_ok/git.log" \
    || fail "tag manifest does not contain the measured source/metadata trees"
[ ! -e "$release_ok/.fixture-commit-hook-ran" ] \
    && [ ! -e "$release_ok/.fixture-commit-msg-hook-ran" ] \
    && [ ! -e "$release_ok/.fixture-reference-hook-ran" ] \
    || fail "release-time metadata commit executed an extensible commit hook"
[ ! -s "$release_ok/secret.log" ] \
    || fail "credential-bearing environment reached CI or an unsigned build phase"
[ "$(head -1 "$release_ok/ci.log")" = "--clean" ] \
    || fail "release artifact build was not preceded by explicit clean local CI"
[ "$(tr '\n' ' ' < "$release_ok/build.log")" = "unsigned-build assemble sign publish " ] \
    || fail "release stages did not run in the credential-isolated order"
release_ok_build_workspace=$(/usr/bin/head -1 "$release_ok/build-pwd.log")
[[ "$release_ok_build_workspace" == /private/tmp/maccrab-release-build.* ]] \
    || fail "release stages did not run in a private tracked-only export"
[ "$(/usr/bin/sort -u "$release_ok/build-pwd.log" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = "1" ] \
    || fail "release stages did not share one pinned tracked-only export"
[ ! -e "$release_ok_build_workspace" ] \
    || fail "successful release leaked its private tracked-only build export"
grep -q 'MacCrab v9.9.11 Released!' "$release_ok/output.log" \
    || fail "release.sh omitted the success banner after the mocked upload"
for expected_publish in appcast-generate appcast-publish release-json cask; do
    if ! grep -q "^${expected_publish}$" "$release_ok/publish.log"; then
        tail -80 "$release_ok/output.log" >&2
        echo "publish log:" >&2
        cat "$release_ok/publish.log" >&2
        fail "full public success path skipped $expected_publish"
    fi
done
if find "$release_ok/tmp" -type f -name 'maccrab-appcast-item.*' | grep -q .; then
    fail "successful appcast publication leaked its temporary item"
fi
release_ok_snapshot=$(cat "$release_ok/snapshot.path")
[ ! -e "$release_ok_snapshot" ] || fail "successful release leaked its private upload snapshot"
assert_no_github_delete "$release_ok/gh.log"
/usr/bin/grep -q 'api --hostname github.com repos/peterhanily/maccrab' "$release_ok/gh.log" \
    || fail "GitHub API was not pinned to canonical host/repository"
! /usr/bin/grep -q '{owner}/{repo}\|attacker/redirected\|evil.invalid' "$release_ok/gh.log" \
    || fail "hostile or placeholder GitHub routing reached the publisher"

# Independently attack the private copy between cp and its validation. The
# upload path must require non-empty bytes before gh ever receives a pathname.
release_zero_snapshot="$TEST_ROOT/release-zero-upload-snapshot"
make_release_fixture "$release_zero_snapshot"
write_executable "$release_zero_snapshot/fake-bin/chmod" \
    '#!/bin/bash' \
    '/bin/chmod "$@"' \
    'if [ "${MACCRAB_TEST_ZERO_UPLOAD_SNAPSHOT:-0}" = "1" ] && [ "${1:-}" = "600" ] && [[ "${2:-}" == */maccrab-release-upload.*/*.dmg ]]; then printf "%s\n" "$2" > "$(dirname "$MACCRAB_TEST_GH_LOG")/snapshot-attempt.path"; : > "$2"; fi'
/usr/bin/sed -i '' \
    "s#/bin/chmod #${release_zero_snapshot}/fake-bin/chmod #g" \
    "$release_zero_snapshot/scripts/release.sh"
/usr/bin/git -C "$release_zero_snapshot" add scripts/release.sh fake-bin/chmod
/usr/bin/git -C "$release_zero_snapshot" -c core.hooksPath=.no-hooks \
    commit -q -m 'inject snapshot fault fixture'
set +e
(
    cd "$release_zero_snapshot"
    PATH="$release_zero_snapshot/fake-bin:/usr/bin:/bin" \
        HOME="$release_zero_snapshot/home" \
        TMPDIR="$release_zero_snapshot/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_ARTIFACT_ATTACK=none \
        MACCRAB_TEST_ZERO_UPLOAD_SNAPSHOT=1 \
        MACCRAB_TEST_GH_STATUS=0 \
        MACCRAB_TEST_GH_LOG="$release_zero_snapshot/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_zero_snapshot/output.log" 2>&1
release_zero_snapshot_status=$?
set -e
[ "$release_zero_snapshot_status" -ne 0 ] || fail "release.sh accepted a zero-byte private upload snapshot"
grep -q 'Private upload snapshot is not a non-empty regular file' "$release_zero_snapshot/output.log" \
    || {
        tail -60 "$release_zero_snapshot/output.log" >&2
        fail "release.sh did not diagnose the zero-byte private upload snapshot"
    }
! grep -q 'release create' "$release_zero_snapshot/gh.log" \
    || fail "release.sh handed gh a zero-byte private upload snapshot"
zero_snapshot_path=$(cat "$release_zero_snapshot/snapshot-attempt.path")
[ ! -e "$(dirname "$zero_snapshot_path")" ] \
    || fail "zero-byte upload-snapshot rejection leaked its private directory"

# Swap the original `.build` pathname from inside the mocked gh invocation.
# The uploaded digest must still come from the already-verified private copy,
# and restoring the original path afterward must let the release complete.
release_upload_swap="$TEST_ROOT/release-upload-swap"
make_release_fixture "$release_upload_swap"
(
    cd "$release_upload_swap"
    PATH="$release_upload_swap/fake-bin:/usr/bin:/bin" \
        HOME="$release_upload_swap/home" \
        TMPDIR="$release_upload_swap/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_ARTIFACT_ATTACK=none \
        MACCRAB_TEST_UPLOAD_SWAP=1 \
        MACCRAB_TEST_GH_STATUS=0 \
        MACCRAB_TEST_GH_LOG="$release_upload_swap/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_upload_swap/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_upload_swap/output.log" 2>&1 \
    || fail "private upload snapshot did not survive an original-path swap"
swap_expected_sha=$(grep -oE '[a-f0-9]{64}' "$release_upload_swap/release.json" | head -1)
swap_remote_sha=$(cat "$release_upload_swap/.fixture-remote-digest")
[ "$swap_remote_sha" = "$swap_expected_sha" ] \
    || fail "gh received bytes other than the verified private snapshot"
grep -q 'Draft asset digest and remote tag verified' "$release_upload_swap/output.log" \
    || fail "upload-swap path omitted immediate remote digest verification"
grep -q 'MacCrab v9.9.11 Released!' "$release_upload_swap/output.log" \
    || fail "verified upload-swap fixture did not complete"

# Once the immutable snapshot exists, even a post-PATCH deletion of the live
# .build pathname must not change the appcast/downstream bytes.
release_post_patch_live="$TEST_ROOT/release-post-patch-live-delete"
make_release_fixture "$release_post_patch_live"
(
    cd "$release_post_patch_live"
    HOME="$release_post_patch_live/home" \
        DEVELOPER_ID="fixture identity" SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main MACCRAB_TEST_POST_PATCH_LIVE_ATTACK=delete \
        MACCRAB_TEST_GH_LOG="$release_post_patch_live/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_post_patch_live/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_post_patch_live/output.log" 2>&1 \
    || fail "immutable snapshot did not survive post-PATCH live-DMG deletion"
[ ! -e "$release_post_patch_live/.build/MacCrab-v9.9.11.dmg" ] \
    || fail "post-PATCH live-delete fixture did not remove the mutable pathname"
for expected_publish in appcast-generate appcast-publish release-json cask; do
    /usr/bin/grep -q "^${expected_publish}$" "$release_post_patch_live/publish.log" \
        || fail "immutable snapshot downstream skipped $expected_publish"
done
post_patch_snapshot=$(cat "$release_post_patch_live/snapshot.path")
[ ! -e "$post_patch_snapshot" ] \
    || fail "post-PATCH success leaked immutable snapshot after downstream completion"
assert_no_github_delete "$release_post_patch_live/gh.log"

# If GitHub reports any other digest, downstream publication must not begin.
# The draft is retained by immutable ID for manual inspection/recovery.
release_remote_mismatch="$TEST_ROOT/release-remote-digest-mismatch"
make_release_fixture "$release_remote_mismatch"
set +e
(
    cd "$release_remote_mismatch"
    PATH="$release_remote_mismatch/fake-bin:/usr/bin:/bin" \
        HOME="$release_remote_mismatch/home" \
        TMPDIR="$release_remote_mismatch/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        SKIP_APPCAST=1 \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_ARTIFACT_ATTACK=none \
        MACCRAB_TEST_GH_STATUS=0 \
        MACCRAB_TEST_REMOTE_DIGEST_OVERRIDE=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
        MACCRAB_TEST_GH_LOG="$release_remote_mismatch/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_remote_mismatch/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_remote_mismatch/output.log" 2>&1
remote_mismatch_status=$?
set -e
[ "$remote_mismatch_status" -ne 0 ] || fail "release.sh accepted a mismatched remote asset digest"
assert_no_github_delete "$release_remote_mismatch/gh.log"
[ "$(cat "$release_remote_mismatch/.fixture-release-id")" = "4242" ] \
    || fail "remote digest mismatch did not retain the exact draft ID"
[ "$(cat "$release_remote_mismatch/.fixture-release-draft")" = "true" ] \
    || fail "remote digest mismatch did not retain draft state"
grep -q 'MANUAL RECOVERY REQUIRED: retained GitHub release ID 4242' "$release_remote_mismatch/output.log" \
    || fail "remote digest mismatch omitted manual recovery identity"
! grep -q 'MacCrab v9.9.11 Released!' "$release_remote_mismatch/output.log" \
    || fail "release.sh printed success after remote digest mismatch"
[ ! -s "$release_remote_mismatch/publish.log" ] \
    || fail "downstream publication started before remote asset verification"

# A client/network error may be reported after GitHub accepted enough of the
# create request to expose a partial release. Detect and retain that record for
# manual recovery rather than relying only on the command's exit status.
release_partial_create="$TEST_ROOT/release-partial-create-failure"
make_release_fixture "$release_partial_create"
set +e
(
    cd "$release_partial_create"
    PATH="$release_partial_create/fake-bin:/usr/bin:/bin" \
        HOME="$release_partial_create/home" \
        TMPDIR="$release_partial_create/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        SKIP_APPCAST=1 \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_ARTIFACT_ATTACK=none \
        MACCRAB_TEST_GH_STATUS=71 \
        MACCRAB_TEST_PARTIAL_GH_CREATE=1 \
        MACCRAB_TEST_GH_LOG="$release_partial_create/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_partial_create/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_partial_create/output.log" 2>&1
partial_create_status=$?
set -e
[ "$partial_create_status" -ne 0 ] || fail "release.sh accepted a partial GitHub create failure"
grep -q 'GitHub draft creation/upload failed (exit 71)' "$release_partial_create/output.log" \
    || fail "partial GitHub create failure was not diagnosed"
assert_no_github_delete "$release_partial_create/gh.log"
[ "$(cat "$release_partial_create/.fixture-release-id")" = "4242" ] \
    || fail "partial create did not retain its exact draft ID"
[ "$(cat "$release_partial_create/.fixture-release-draft")" = "true" ] \
    || fail "partial create did not retain draft state"
grep -q 'MANUAL RECOVERY REQUIRED: retained GitHub release ID 4242' "$release_partial_create/output.log" \
    || fail "partial-create failure omitted manual recovery identity"
[ ! -s "$release_partial_create/publish.log" ] \
    || fail "downstream publication began after a partial GitHub create failure"

# A concurrent actor can create a release for the same tag after the initial
# authoritative 404 but before our draft create completes. Ownership requires
# this run's nonce, so a conflicting draft ID must never be deleted.
release_concurrent="$TEST_ROOT/release-concurrent-owner"
make_release_fixture "$release_concurrent"
set +e
(
    cd "$release_concurrent"
    PATH="$release_concurrent/fake-bin:/usr/bin:/bin" \
        HOME="$release_concurrent/home" \
        TMPDIR="$release_concurrent/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_CONCURRENT_RELEASE=1 \
        MACCRAB_TEST_GH_LOG="$release_concurrent/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_concurrent/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_concurrent/output.log" 2>&1
concurrent_status=$?
set -e
[ "$concurrent_status" -ne 0 ] || fail "concurrent unowned GitHub draft was treated as owned"
grep -q 'leaving unowned ID 5252 untouched' "$release_concurrent/output.log" \
    || fail "concurrent unowned release was not identified by immutable ID"
assert_no_github_delete "$release_concurrent/gh.log"
[ "$(cat "$release_concurrent/.fixture-release-id")" = "5252" ] \
    || fail "concurrent release state did not survive the failed run"
[ ! -s "$release_concurrent/publish.log" ] \
    || fail "downstream publication started after a concurrent release race"

# If a PATCH transport response is lost but the exact immutable release ID is
# observably published with the requested state, continue safely. Conversely,
# a non-draft but wrong state is ambiguous and must be left untouched.
release_patch_lost="$TEST_ROOT/release-patch-response-lost"
make_release_fixture "$release_patch_lost"
(
    cd "$release_patch_lost"
    PATH="$release_patch_lost/fake-bin:/usr/bin:/bin" \
        HOME="$release_patch_lost/home" \
        TMPDIR="$release_patch_lost/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_PATCH_STATUS=70 \
        MACCRAB_TEST_GH_LOG="$release_patch_lost/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_patch_lost/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_patch_lost/output.log" 2>&1 \
    || fail "verified exact-ID publication did not survive a lost PATCH response"
grep -q 'Verified GitHub release published: .* (ID 4242)' "$release_patch_lost/output.log" \
    || fail "lost PATCH response was not resolved by exact-ID state verification"
assert_no_github_delete "$release_patch_lost/gh.log"

release_patch_draft="$TEST_ROOT/release-patch-failed-stays-draft"
make_release_fixture "$release_patch_draft"
set +e
(
    cd "$release_patch_draft"
    PATH="$release_patch_draft/fake-bin:/usr/bin:/bin" \
        HOME="$release_patch_draft/home" \
        TMPDIR="$release_patch_draft/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_PATCH_STATUS=70 \
        MACCRAB_TEST_PUBLISH_STAYS_DRAFT=1 \
        MACCRAB_TEST_GH_LOG="$release_patch_draft/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_patch_draft/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_patch_draft/output.log" 2>&1
patch_draft_status=$?
set -e
[ "$patch_draft_status" -ne 0 ] || fail "failed PATCH that stayed draft was accepted"
[ "$(cat "$release_patch_draft/.fixture-release-id")" = "4242" ] \
    && [ "$(cat "$release_patch_draft/.fixture-release-draft")" = "true" ] \
    || fail "failed PATCH did not retain exact draft state"
grep -q 'MANUAL RECOVERY REQUIRED: retained GitHub release ID 4242' \
        "$release_patch_draft/output.log" \
    || fail "failed PATCH omitted manual recovery identity"
assert_no_github_delete "$release_patch_draft/gh.log"
[ ! -s "$release_patch_draft/publish.log" ] \
    || fail "downstream publication began after failed PATCH"

release_ambiguous="$TEST_ROOT/release-ambiguous-published-state"
make_release_fixture "$release_ambiguous"
set +e
(
    cd "$release_ambiguous"
    PATH="$release_ambiguous/fake-bin:/usr/bin:/bin" \
        HOME="$release_ambiguous/home" \
        TMPDIR="$release_ambiguous/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_PATCH_STATUS=70 \
        MACCRAB_TEST_PATCH_WRONG_PUBLISHED=1 \
        MACCRAB_TEST_GH_LOG="$release_ambiguous/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_ambiguous/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_ambiguous/output.log" 2>&1
ambiguous_status=$?
set -e
[ "$ambiguous_status" -ne 0 ] || fail "ambiguous exact-ID publication state was accepted"
grep -q 'Publication state is ambiguous; leaving it untouched' "$release_ambiguous/output.log" \
    || fail "ambiguous publication state was not reported"
assert_no_github_delete "$release_ambiguous/gh.log"
[ "$(cat "$release_ambiguous/.fixture-release-id")" = "4242" ] \
    || fail "ambiguous exact release ID did not remain for manual inspection"
[ ! -s "$release_ambiguous/publish.log" ] \
    || fail "downstream publication started from ambiguous GitHub state"

release_post_publish_swap="$TEST_ROOT/release-post-publish-asset-swap"
make_release_fixture "$release_post_publish_swap"
set +e
(
    cd "$release_post_publish_swap"
    PATH="$release_post_publish_swap/fake-bin:/usr/bin:/bin" \
        HOME="$release_post_publish_swap/home" \
        TMPDIR="$release_post_publish_swap/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_POST_PUBLISH_DIGEST_OVERRIDE=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
        MACCRAB_TEST_GH_LOG="$release_post_publish_swap/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_post_publish_swap/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_post_publish_swap/output.log" 2>&1
post_publish_swap_status=$?
set -e
[ "$post_publish_swap_status" -ne 0 ] || fail "post-publication asset swap passed final verification"
grep -q 'Publication state is ambiguous; leaving it untouched' "$release_post_publish_swap/output.log" \
    || fail "post-publication asset mismatch was not left for manual inspection"
assert_no_github_delete "$release_post_publish_swap/gh.log"
[ ! -s "$release_post_publish_swap/publish.log" ] \
    || fail "downstream publication started after the public asset changed"

# RCs are build-only by default. An explicit public RC is isolated to a GitHub
# prerelease and must leave every production distribution surface byte-for-byte
# unchanged.
release_rc_blocked="$TEST_ROOT/release-rc-build-only-default"
make_release_fixture "$release_rc_blocked"
rc_blocked_json_sha=$(shasum -a 256 "$release_rc_blocked/release.json" | awk '{print $1}')
rc_blocked_cask_sha=$(shasum -a 256 "$release_rc_blocked/Casks/maccrab.rb" | awk '{print $1}')
set +e
(
    cd "$release_rc_blocked"
    PATH="$release_rc_blocked/fake-bin:/usr/bin:/bin" \
        HOME="$release_rc_blocked/home" \
        DEVELOPER_ID="fixture identity" \
        MACCRAB_TEST_GH_LOG="$release_rc_blocked/gh.log" \
        ./scripts/release.sh 9.9.11-rc.1 --skip-prerelease-check
) > "$release_rc_blocked/output.log" 2>&1
rc_blocked_status=$?
set -e
[ "$rc_blocked_status" -ne 0 ] || fail "RC was publicly released without --publish-rc"
grep -q 'will not put an RC on a public channel implicitly' "$release_rc_blocked/output.log" \
    || fail "build-only RC default was not explained"
[ ! -s "$release_rc_blocked/build.log" ] \
    || fail "implicit RC publication attempt started the release build"
[ "$(shasum -a 256 "$release_rc_blocked/release.json" | awk '{print $1}')" = "$rc_blocked_json_sha" ] \
    || fail "blocked RC changed production release.json"
[ "$(shasum -a 256 "$release_rc_blocked/Casks/maccrab.rb" | awk '{print $1}')" = "$rc_blocked_cask_sha" ] \
    || fail "blocked RC changed the production cask"

release_rc="$TEST_ROOT/release-explicit-rc"
make_release_fixture "$release_rc"
rc_json_sha=$(shasum -a 256 "$release_rc/release.json" | awk '{print $1}')
rc_cask_sha=$(shasum -a 256 "$release_rc/Casks/maccrab.rb" | awk '{print $1}')
rc_legacy_cask_sha=$(shasum -a 256 "$release_rc/homebrew/maccrab.rb" | awk '{print $1}')
(
    cd "$release_rc"
    PATH="$release_rc/fake-bin:/usr/bin:/bin" \
        HOME="$release_rc/home" \
        TMPDIR="$release_rc/tmp" \
        DEVELOPER_ID="fixture identity" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_GH_LOG="$release_rc/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_rc/publish.log" \
        ./scripts/release.sh 9.9.11-rc.1 --skip-prerelease-check --publish-rc
) > "$release_rc/output.log" 2>&1 \
    || {
        tail -60 "$release_rc/output.log" >&2
        fail "explicit isolated GitHub RC publication was rejected"
    }
grep -q 'release create --repo peterhanily/maccrab v9.9.11-rc.1 .* --draft --verify-tag --prerelease --latest=false' "$release_rc/gh.log" \
    || fail "RC draft was not created as a verified non-latest prerelease"
grep -q 'MacCrab v9.9.11-rc.1 Prerelease Published' "$release_rc/output.log" \
    || fail "explicit RC path omitted its distinct prerelease banner"
[ ! -s "$release_rc/publish.log" ] \
    || fail "RC invoked a production appcast/site/cask publisher"
[ "$(shasum -a 256 "$release_rc/release.json" | awk '{print $1}')" = "$rc_json_sha" ] \
    || fail "RC rewrote production release.json"
[ "$(shasum -a 256 "$release_rc/Casks/maccrab.rb" | awk '{print $1}')" = "$rc_cask_sha" ] \
    || fail "RC rewrote Casks/maccrab.rb"
[ "$(shasum -a 256 "$release_rc/homebrew/maccrab.rb" | awk '{print $1}')" = "$rc_legacy_cask_sha" ] \
    || fail "RC rewrote homebrew/maccrab.rb"

# Conversely, an already-existing release is not owned by this run. Abort
# before tag mutation/upload and never invoke the rollback path against it.
release_preexisting="$TEST_ROOT/release-preexisting-github-release"
make_release_fixture "$release_preexisting"
printf '%064d\n' 0 > "$release_preexisting/.fixture-remote-digest"
set +e
(
    cd "$release_preexisting"
    PATH="$release_preexisting/fake-bin:/usr/bin:/bin" \
        HOME="$release_preexisting/home" \
        TMPDIR="$release_preexisting/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        SKIP_APPCAST=1 \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_GH_STATUS=0 \
        MACCRAB_TEST_GH_LOG="$release_preexisting/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_preexisting/output.log" 2>&1
preexisting_status=$?
set -e
[ "$preexisting_status" -ne 0 ] || fail "release.sh attempted to replace a pre-existing GitHub release"
grep -q 'GitHub release v9.9.11 already exists' "$release_preexisting/output.log" \
    || fail "pre-existing GitHub release was not diagnosed"
! grep -q 'release create\|release delete' "$release_preexisting/gh.log" \
    || fail "release.sh created or deleted a GitHub release it did not own"

# A transport/auth/API failure is not a 404 and therefore cannot establish
# rollback ownership. Fail closed instead of treating every non-zero probe as
# proof that the release is absent.
release_probe_error="$TEST_ROOT/release-probe-error"
make_release_fixture "$release_probe_error"
set +e
(
    cd "$release_probe_error"
    PATH="$release_probe_error/fake-bin:/usr/bin:/bin" \
        HOME="$release_probe_error/home" \
        TMPDIR="$release_probe_error/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        SKIP_APPCAST=1 \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_GH_STATUS=0 \
        MACCRAB_TEST_RELEASE_PROBE_ERROR=1 \
        MACCRAB_TEST_GH_LOG="$release_probe_error/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_probe_error/output.log" 2>&1
release_probe_error_status=$?
set -e
[ "$release_probe_error_status" -ne 0 ] || fail "release.sh treated an indeterminate GitHub probe as absence"
grep -q 'Could not prove GitHub release v9.9.11 is absent' "$release_probe_error/output.log" \
    || fail "indeterminate GitHub release probe was not diagnosed"
! grep -q 'release create\|release delete' "$release_probe_error/gh.log" \
    || fail "release.sh mutated GitHub state after an indeterminate absence probe"

# SKIP_APPCAST means exactly that: Sparkle is omitted deliberately, while the
# already-public GitHub release still requires site metadata + Homebrew cask.
release_skip_appcast="$TEST_ROOT/release-skip-appcast"
make_release_fixture "$release_skip_appcast"
(
    cd "$release_skip_appcast"
    PATH="$release_skip_appcast/fake-bin:/usr/bin:/bin" \
        HOME="$release_skip_appcast/home" \
        TMPDIR="$release_skip_appcast/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        SKIP_APPCAST=1 \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_ARTIFACT_ATTACK=none \
        MACCRAB_TEST_GH_STATUS=0 \
        MACCRAB_TEST_GH_LOG="$release_skip_appcast/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_skip_appcast/publish.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_skip_appcast/output.log" 2>&1 \
    || fail "SKIP_APPCAST prevented mandatory non-Sparkle publication"
! grep -q '^appcast-' "$release_skip_appcast/publish.log" \
    || fail "SKIP_APPCAST still invoked an appcast tool"
for expected_publish in release-json cask; do
    grep -q "^${expected_publish}$" "$release_skip_appcast/publish.log" \
        || fail "SKIP_APPCAST incorrectly skipped $expected_publish"
done
grep -q 'MacCrab v9.9.11 Released!' "$release_skip_appcast/output.log" \
    || fail "valid Sparkle-only skip did not complete after other publishers succeeded"

# Publisher preflight: the old manual-upload branch reached the final success
# banner without creating a GitHub release. Prove a missing gh executable now
# aborts before even the mocked build/notarization step.
noncanonical_origin="$TEST_ROOT/release-noncanonical-origin"
make_release_fixture "$noncanonical_origin"
/usr/bin/git -C "$noncanonical_origin" remote set-url origin https://github.com/attacker/maccrab.git
set +e
(
    cd "$noncanonical_origin"
    HOME="$noncanonical_origin/home" DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        MACCRAB_TEST_GH_LOG="$noncanonical_origin/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$noncanonical_origin/output.log" 2>&1
noncanonical_origin_status=$?
set -e
[ "$noncanonical_origin_status" -ne 0 ] || fail "release accepted a noncanonical origin"
/usr/bin/grep -q 'origin is not the canonical MacCrab repository' \
        "$noncanonical_origin/output.log" \
    || fail "noncanonical origin was not diagnosed"
[ ! -s "$noncanonical_origin/build.log" ] \
    || fail "release built before canonical-origin validation"

mutated_origin="$TEST_ROOT/release-origin-mutated-after-branch"
make_release_fixture "$mutated_origin"
set +e
(
    cd "$mutated_origin"
    HOME="$mutated_origin/home" DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        MACCRAB_TEST_MUTATE_ORIGIN_AFTER_BRANCH=1 \
        MACCRAB_TEST_GH_LOG="$mutated_origin/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$mutated_origin/output.log" 2>&1
mutated_origin_status=$?
set -e
[ "$mutated_origin_status" -ne 0 ] \
    || fail "release accepted an origin changed by the branch-push gate"
/usr/bin/grep -q 'origin is not the canonical MacCrab repository' \
        "$mutated_origin/output.log" \
    || fail "post-branch canonical-origin mutation was not diagnosed"
! /usr/bin/grep -q 'release create' "$mutated_origin/gh.log" \
    || fail "release publication began after the origin changed"

gh_missing="$TEST_ROOT/release-gh-missing"
make_release_fixture "$gh_missing"
rm "$gh_missing/fake-bin/gh"
/usr/bin/git -C "$gh_missing" add -u fake-bin/gh
/usr/bin/git -C "$gh_missing" -c core.hooksPath=.no-hooks \
    commit -q -m 'remove gh for missing-cli fixture'
set +e
(
    cd "$gh_missing"
    PATH="$gh_missing/fake-bin:/usr/bin:/bin" \
        HOME="$gh_missing/home" \
        DEVELOPER_ID="fixture identity" \
        SKIP_APPCAST=1 \
        MACCRAB_TEST_GH_LOG="$gh_missing/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$gh_missing/output.log" 2>&1
gh_missing_status=$?
set -e
[ "$gh_missing_status" -ne 0 ] || fail "release.sh exited 0 without gh"
if ! grep -q 'GitHub CLI (gh) is required' "$gh_missing/output.log"; then
    /usr/bin/tail -40 "$gh_missing/output.log" >&2
    fail "release.sh did not diagnose missing gh"
fi
[ -s "$gh_missing/.build/MacCrab-v9.9.11.dmg" ] \
    || fail "release.sh did not preserve the local candidate before publisher preflight"

# A present CLI with an expired token is no more useful than a missing CLI.
# Publisher preflight runs only after the local candidate qualifies; it must
# still fail before tag/release mutation and never reach `gh release create`.
gh_unauthenticated="$TEST_ROOT/release-gh-unauthenticated"
make_release_fixture "$gh_unauthenticated"
set +e
(
    cd "$gh_unauthenticated"
    PATH="$gh_unauthenticated/fake-bin:/usr/bin:/bin" \
        HOME="$gh_unauthenticated/home" \
        DEVELOPER_ID="fixture identity" \
        SKIP_APPCAST=1 \
        MACCRAB_TEST_GH_PREFLIGHT_STATUS=1 \
        MACCRAB_TEST_GH_LOG="$gh_unauthenticated/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$gh_unauthenticated/output.log" 2>&1
gh_unauthenticated_status=$?
set -e
[ "$gh_unauthenticated_status" -ne 0 ] || fail "release.sh exited 0 with invalid gh authentication"
grep -q 'GitHub CLI authentication is invalid or expired' "$gh_unauthenticated/output.log" \
    || fail "release.sh did not diagnose invalid gh authentication"
[ -s "$gh_unauthenticated/.build/MacCrab-v9.9.11.dmg" ] \
    || fail "release.sh did not preserve the candidate before validating gh authentication"
! grep -q 'release create' "$gh_unauthenticated/gh.log" \
    || fail "release.sh attempted release creation with invalid gh authentication"

# Authentication alone is insufficient: read-only repository credentials can
# inspect the project but cannot attach an asset to the release.
gh_readonly="$TEST_ROOT/release-gh-readonly"
make_release_fixture "$gh_readonly"
set +e
(
    cd "$gh_readonly"
    PATH="$gh_readonly/fake-bin:/usr/bin:/bin" \
        HOME="$gh_readonly/home" \
        DEVELOPER_ID="fixture identity" \
        SKIP_APPCAST=1 \
        MACCRAB_TEST_GH_PUSH_PERMISSION=false \
        MACCRAB_TEST_GH_LOG="$gh_readonly/gh.log" \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$gh_readonly/output.log" 2>&1
gh_readonly_status=$?
set -e
[ "$gh_readonly_status" -ne 0 ] || fail "release.sh exited 0 with read-only repository credentials"
grep -q 'cannot publish to this repository' "$gh_readonly/output.log" \
    || fail "release.sh did not diagnose read-only repository credentials"
[ -s "$gh_readonly/.build/MacCrab-v9.9.11.dmg" ] \
    || fail "release.sh did not preserve the candidate before validating repository write access"
! grep -q 'release create' "$gh_readonly/gh.log" \
    || fail "release.sh attempted release creation with read-only repository credentials"

# release.sh is a public publisher, not a build-only command. Sparkle may be
# deliberately skipped, but the site metadata/cask publisher token remains a
# hard precondition before tag/publish work; local candidate construction does
# not need publisher credentials.
site_token_missing="$TEST_ROOT/release-site-token-missing"
make_release_fixture "$site_token_missing"
set +e
(
    cd "$site_token_missing"
    PATH="$site_token_missing/fake-bin:/usr/bin:/bin" \
        HOME="$site_token_missing/home" \
        DEVELOPER_ID="fixture identity" \
        SKIP_APPCAST=1 \
        MACCRAB_TEST_GH_LOG="$site_token_missing/gh.log" \
        env -u SITE_REPO_TOKEN \
            ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$site_token_missing/output.log" 2>&1
site_token_missing_status=$?
set -e
[ "$site_token_missing_status" -ne 0 ] || fail "release.sh exited 0 without SITE_REPO_TOKEN"
grep -q 'SITE_REPO_TOKEN env var not set' "$site_token_missing/output.log" \
    || fail "release.sh did not diagnose missing distribution token"
[ -s "$site_token_missing/.build/MacCrab-v9.9.11.dmg" ] \
    || fail "release.sh did not preserve the candidate before validating SITE_REPO_TOKEN"
! grep -q 'release create' "$site_token_missing/gh.log" \
    || fail "release.sh published GitHub release without the distribution token"

# Defense in depth: even if a future hook regresses, release.sh must refuse to
# publish when the artifact is absent or differs from the bytes validated before
# the tag was pushed.
run_release_attack delete 'Release artifact disappeared'
run_release_attack zero 'became empty/non-regular'
run_release_attack mutate 'Release artifact changed during the push/CI gate'

run_publish_failure() {
    local failure="$1"
    local expected_message="$2"
    local fixture="$TEST_ROOT/release-publish-$failure"
    make_release_fixture "$fixture"
    case "$failure" in
        APPCAST_GENERATE_STATUS) : > "$fixture/fail-appcast-generate" ;;
        APPCAST_PUBLISH_STATUS) : > "$fixture/fail-appcast-publish" ;;
    esac
    set +e
    (
        cd "$fixture"
        PATH="$fixture/fake-bin:/usr/bin:/bin" \
            HOME="$fixture/home" \
            TMPDIR="$fixture/tmp" \
            DEVELOPER_ID="fixture identity" \
            SITE_REPO_TOKEN="fixture token" \
            RELEASE_BRANCH=main \
            MACCRAB_TEST_GH_STATUS=0 \
            MACCRAB_TEST_GH_LOG="$fixture/gh.log" \
            MACCRAB_TEST_PUBLISH_LOG="$fixture/publish.log" \
            env "MACCRAB_TEST_${failure}=1" \
                ./scripts/release.sh 9.9.11 --skip-prerelease-check
    ) > "$fixture/output.log" 2>&1
    local status=$?
    set -e
    [ "$status" -ne 0 ] || fail "release.sh exited 0 after $failure"
    grep -q "$expected_message" "$fixture/output.log" \
        || fail "release.sh did not report $failure"
    grep -q 'RELEASE INCOMPLETE' "$fixture/output.log" \
        || fail "release.sh did not print the incomplete banner after $failure"
    ! grep -q 'MacCrab v9.9.11 Released!' "$fixture/output.log" \
        || fail "release.sh printed a success banner after $failure"
    grep -q '^release-json$' "$fixture/publish.log" \
        || fail "release.json publication did not run after $failure"
    grep -q '^cask$' "$fixture/publish.log" \
        || fail "cask publication did not run after $failure"
    if [ "$failure" = "APPCAST_PUBLISH_STATUS" ]; then
        grep -q 'Appcast recovery item retained:' "$fixture/output.log" \
            || fail "appcast publish failure did not print a retained recovery item"
        recovery_item=$(sed -n 's/^  ! Appcast recovery item retained: //p' \
            "$fixture/output.log" | tail -1)
        [ -n "$recovery_item" ] && [ -f "$recovery_item" ] \
            || fail "appcast publish failure deleted the advertised recovery item"
        rm -f "$recovery_item"
    fi
}

run_publish_failure APPCAST_GENERATE_STATUS 'appcast generation failed'
run_publish_failure APPCAST_PUBLISH_STATUS 'appcast publish failed'
run_publish_failure CASK_PUBLISH_STATUS 'cask publish failed'

# Aggregation must count multiple independent failures while still attempting
# every later publisher. This is the contract that prevents the first outage
# from hiding a second stale distribution surface.
release_multi_fail="$TEST_ROOT/release-multiple-publish-failures"
make_release_fixture "$release_multi_fail"
: > "$release_multi_fail/fail-appcast-publish"
set +e
(
    cd "$release_multi_fail"
    PATH="$release_multi_fail/fake-bin:/usr/bin:/bin" \
        HOME="$release_multi_fail/home" \
        TMPDIR="$release_multi_fail/tmp" \
        DEVELOPER_ID="fixture identity" \
        SITE_REPO_TOKEN="fixture token" \
        RELEASE_BRANCH=main \
        MACCRAB_TEST_GH_STATUS=0 \
        MACCRAB_TEST_GH_LOG="$release_multi_fail/gh.log" \
        MACCRAB_TEST_PUBLISH_LOG="$release_multi_fail/publish.log" \
        MACCRAB_TEST_APPCAST_PUBLISH_STATUS=1 \
        MACCRAB_TEST_CASK_PUBLISH_STATUS=1 \
        ./scripts/release.sh 9.9.11 --skip-prerelease-check
) > "$release_multi_fail/output.log" 2>&1
multi_fail_status=$?
set -e
[ "$multi_fail_status" -ne 0 ] || fail "release.sh exited 0 after multiple publisher failures"
grep -q '2 publish step(s) did not land' "$release_multi_fail/output.log" \
    || fail "release.sh did not aggregate exactly two independent failures"
grep -q '^release-json$' "$release_multi_fail/publish.log" \
    || fail "release.json did not run between multiple publisher failures"
grep -q '^cask$' "$release_multi_fail/publish.log" \
    || fail "cask publisher was not attempted in the multiple-failure case"
grep -q 'RELEASE INCOMPLETE' "$release_multi_fail/output.log" \
    || fail "multiple publisher failures lacked the incomplete banner"
multi_recovery_item=$(sed -n 's/^  ! Appcast recovery item retained: //p' \
    "$release_multi_fail/output.log" | tail -1)
[ -z "$multi_recovery_item" ] || rm -f "$multi_recovery_item"

while IFS= read -r github_log; do
    assert_no_github_delete "$github_log"
done < <(/usr/bin/find "$TEST_ROOT" -name gh.log -type f -print)

# Two concurrent --clean runs used to be able to destroy the notarized DMG: the
# second globs .build while the first has the artifact staged aside, preserves
# nothing, installs no restore trap, and then `rm -rf .build`. The lock must
# refuse BEFORE any destructive step, so a refusal leaves .build untouched.
ci_lock_busy="$TEST_ROOT/ci-lock-busy"
make_ci_fixture "$ci_lock_busy"
mkdir -p "$ci_lock_busy/.build"
printf 'signed-and-notarized\n' > "$ci_lock_busy/.build/MacCrab-v9.9.30.dmg"
busy_dmg_sha=$(shasum -a 256 "$ci_lock_busy/.build/MacCrab-v9.9.30.dmg" | awk '{print $1}')
mkdir -p "$ci_lock_busy/.maccrab-ci-clean.lock"
# $$ is this test process: alive for the duration, so the lock is never stale.
printf '%s\n' "$$" > "$ci_lock_busy/.maccrab-ci-clean.lock/pid"
set +e
(
    cd "$ci_lock_busy"
    PATH="$ci_lock_busy/fake-bin:/usr/bin:/bin" \
        TMPDIR="$ci_lock_busy/tmp" \
        MACCRAB_TEST_SWIFT_LOG="$ci_lock_busy/swift.log" \
        ./scripts/ci-local.sh --clean \
            --expect-release-dmg .build/MacCrab-v9.9.30.dmg "$busy_dmg_sha"
) > "$ci_lock_busy/output.log" 2>&1
lock_busy_status=$?
set -e
[ "$lock_busy_status" -ne 0 ] || fail "clean CI ran while another run held the release lock"
grep -q 'holds the release-artifact lock' "$ci_lock_busy/output.log" \
    || fail "concurrent clean CI did not diagnose the held release lock"
[ -d "$ci_lock_busy/.build" ] || fail "lock refusal deleted .build"
[ "$(shasum -a 256 "$ci_lock_busy/.build/MacCrab-v9.9.30.dmg" | awk '{print $1}')" = "$busy_dmg_sha" ] \
    || fail "lock refusal disturbed the release DMG"
[ -d "$ci_lock_busy/.maccrab-ci-clean.lock" ] \
    || fail "refused run removed the lock belonging to the live holder"
if find "$ci_lock_busy" -maxdepth 1 -type d -name '.maccrab-ci-release.*' | grep -q .; then
    fail "lock refusal created a staging directory"
fi

# A lock whose owner is provably dead must not wedge the release forever.
ci_lock_stale="$TEST_ROOT/ci-lock-stale"
make_ci_fixture "$ci_lock_stale"
mkdir -p "$ci_lock_stale/.build"
printf 'signed-and-notarized\n' > "$ci_lock_stale/.build/MacCrab-v9.9.31.dmg"
stale_dmg_sha=$(shasum -a 256 "$ci_lock_stale/.build/MacCrab-v9.9.31.dmg" | awk '{print $1}')
mkdir -p "$ci_lock_stale/.maccrab-ci-clean.lock"
# A PID that has certainly exited: spawn one and wait for it.
( exit 0 ) & dead_pid=$!
wait "$dead_pid" 2>/dev/null || true
printf '%s\n' "$dead_pid" > "$ci_lock_stale/.maccrab-ci-clean.lock/pid"
set +e
(
    cd "$ci_lock_stale"
    PATH="$ci_lock_stale/fake-bin:/usr/bin:/bin" \
        TMPDIR="$ci_lock_stale/tmp" \
        MACCRAB_TEST_SWIFT_LOG="$ci_lock_stale/swift.log" \
        ./scripts/ci-local.sh --clean \
            --expect-release-dmg .build/MacCrab-v9.9.31.dmg "$stale_dmg_sha"
) > "$ci_lock_stale/output.log" 2>&1
set -e
grep -q 'clearing a stale release lock' "$ci_lock_stale/output.log" \
    || fail "clean CI did not break a lock whose owner is dead"
grep -q 'holds the release-artifact lock' "$ci_lock_stale/output.log" \
    && fail "clean CI refused despite the lock owner being dead"
[ "$(shasum -a 256 "$ci_lock_stale/.build/MacCrab-v9.9.31.dmg" | awk '{print $1}')" = "$stale_dmg_sha" ] \
    || fail "stale-lock recovery did not preserve the release DMG"

echo "PASS: release artifacts and publisher failure paths are fail-closed"
