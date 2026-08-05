#!/bin/bash
# ci-local.sh — Run all CI checks locally (replaces GitHub Actions)
set -euo pipefail

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
# Swift Testing schedules test functions concurrently independently of
# SwiftPM's `--no-parallel` process-level setting. Several MacCrab tests
# deliberately exercise utility-priority work; letting the framework fan all
# 4,000+ tests out at once can starve that executor long enough to manufacture
# lifecycle timeouts. Keep release qualification deterministic and bounded.
SWT_EXPERIMENTAL_MAXIMUM_PARALLELIZATION_WIDTH=1
export SWT_EXPERIMENTAL_MAXIMUM_PARALLELIZATION_WIDTH
SCRIPT_DIR="$(cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)"
PROJECT_DIR="$(/usr/bin/dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
    GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE GIT_PREFIX GIT_CONFIG \
    GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM GIT_CONFIG_COUNT \
    GIT_CONFIG_PARAMETERS GIT_EXEC_PATH GIT_CEILING_DIRECTORIES \
    GIT_DISCOVERY_ACROSS_FILESYSTEM
GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_REPLACE_OBJECTS

GIT_BIN=/usr/bin/git
AWK_BIN=/usr/bin/awk
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

# --clean: wipe the Swift build tree and re-resolve before running. Release
# DMGs also live under .build, so they are moved aside and restored byte-for-byte
# across the wipe. A tag push invokes this script after release.sh has already
# signed, notarized and stapled its DMG; deleting that artifact here strands the
# tag with nothing for `gh release create` to upload.
#
# Local CI runs on the machine that already has the toolchain, a warm .build and
# resolved dependencies — so it cannot see environment drift the way a hosted
# runner on a fresh image could. That difference is exactly the "green locally,
# red in CI" class this project has been bitten by before (a poisoned /tmp cache,
# Xcode integer-literal arithmetic inside #expect, `runner` colliding with a
# sanitizer reserved word). The pre-push hook passes --clean automatically on a
# TAG push, so every release is gated on a from-scratch build.
CLEAN_TREE=0
EXPECTED_RELEASE_COUNT=0
EXPECTED_RELEASE_PATHS=()
EXPECTED_RELEASE_SHAS=()
EXPECTED_RELEASE_COMMIT=""
EXPECTED_RELEASE_SOURCE_COMMIT=""
EXPECTED_RELEASE_SOURCE_TREE=""
EXPECTED_RELEASE_METADATA_TREE=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --clean)
            CLEAN_TREE=1
            shift
            ;;
        --expect-release-dmg)
            if [ "$#" -lt 3 ]; then
                echo "--expect-release-dmg requires PATH and SHA256" >&2
                exit 2
            fi
            expected_path=$2
            expected_sha=$3
            expected_leaf=${expected_path#.build/}
            case "$expected_path" in
                .build/MacCrab-v*.dmg) ;;
                *) echo "unsafe expected release DMG path: $expected_path" >&2; exit 2 ;;
            esac
            case "$expected_leaf" in
                */*) echo "unsafe expected release DMG path: $expected_path" >&2; exit 2 ;;
            esac
            if ! [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
                echo "invalid expected release SHA-256: $expected_sha" >&2
                exit 2
            fi
            EXPECTED_RELEASE_PATHS[$EXPECTED_RELEASE_COUNT]=$expected_path
            EXPECTED_RELEASE_SHAS[$EXPECTED_RELEASE_COUNT]=$expected_sha
            EXPECTED_RELEASE_COUNT=$((EXPECTED_RELEASE_COUNT + 1))
            shift 3
            ;;
        --expect-release-commit)
            if [ "$#" -lt 2 ]; then
                echo "--expect-release-commit requires an object ID" >&2
                exit 2
            fi
            if [ -n "$EXPECTED_RELEASE_COMMIT" ]; then
                echo "--expect-release-commit may be supplied only once" >&2
                exit 2
            fi
            if ! [[ "$2" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
                echo "invalid expected release commit object ID: $2" >&2
                exit 2
            fi
            EXPECTED_RELEASE_COMMIT=$2
            shift 2
            ;;
        --expect-release-source)
            if [ "$#" -lt 3 ] || [ -n "$EXPECTED_RELEASE_SOURCE_COMMIT" ]; then
                echo "--expect-release-source requires one COMMIT TREE pair" >&2
                exit 2
            fi
            if ! [[ "$2" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
                    || ! [[ "$3" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
                echo "invalid expected release source commit/tree object ID" >&2
                exit 2
            fi
            EXPECTED_RELEASE_SOURCE_COMMIT=$2
            EXPECTED_RELEASE_SOURCE_TREE=$3
            shift 3
            ;;
        --expect-release-metadata-tree)
            if [ "$#" -lt 2 ] || [ -n "$EXPECTED_RELEASE_METADATA_TREE" ]; then
                echo "--expect-release-metadata-tree requires one TREE" >&2
                exit 2
            fi
            if ! [[ "$2" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
                echo "invalid expected release metadata tree object ID" >&2
                exit 2
            fi
            EXPECTED_RELEASE_METADATA_TREE=$2
            shift 2
            ;;
        -h|--help)
            echo "usage: ci-local.sh [--clean] [--expect-release-commit OID] [--expect-release-source COMMIT TREE] [--expect-release-metadata-tree TREE] [--expect-release-dmg PATH SHA256]"
            echo "  --clean   wipe Swift build outputs and re-resolve; preserve release DMGs"
            echo "  --expect-release-commit  pin HEAD, source tree, and executing hook"
            echo "  --expect-release-dmg  require and preserve these exact release bytes"
            exit 0
            ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [ "$EXPECTED_RELEASE_COUNT" -gt 0 ] && [ "$CLEAN_TREE" != "1" ]; then
    echo "--expect-release-dmg requires --clean" >&2
    exit 2
fi
if [ -n "$EXPECTED_RELEASE_COMMIT" ]; then
    if [ "$CLEAN_TREE" != "1" ]; then
        echo "--expect-release-commit requires --clean" >&2
        exit 2
    fi
    if [ "$EXPECTED_RELEASE_COUNT" -eq 0 ]; then
        echo "--expect-release-commit requires at least one --expect-release-dmg manifest entry" >&2
        exit 2
    fi
    if [ -z "$EXPECTED_RELEASE_SOURCE_COMMIT" ] \
            || [ -z "$EXPECTED_RELEASE_SOURCE_TREE" ] \
            || [ -z "$EXPECTED_RELEASE_METADATA_TREE" ]; then
        echo "--expect-release-commit requires source commit/tree and metadata tree" >&2
        exit 2
    fi
elif [ -n "$EXPECTED_RELEASE_SOURCE_COMMIT" ] \
        || [ -n "$EXPECTED_RELEASE_SOURCE_TREE" ] \
        || [ -n "$EXPECTED_RELEASE_METADATA_TREE" ]; then
    echo "release source/tree manifests require --expect-release-commit" >&2
    exit 2
fi

reject_hidden_release_index_state() {
    [ -n "$EXPECTED_RELEASE_COMMIT" ] || return 0
    local hidden
    hidden=$($GIT_BIN ls-files -v | $AWK_BIN 'substr($0,1,1) == "S" || substr($0,1,1) ~ /^[a-z]$/ { print }')
    if [ -n "$hidden" ]; then
        echo "ERROR: clean release CI found assume-unchanged/skip-worktree entries:" >&2
        printf '%s\n' "$hidden" >&2
        return 1
    fi
    if ! $GIT_BIN update-index --really-refresh >/dev/null 2>&1 \
            || ! $GIT_BIN diff-files --quiet -- \
            || ! $GIT_BIN diff-index --cached --quiet HEAD --; then
        echo "ERROR: clean release CI index/worktree differs from HEAD after forced refresh" >&2
        return 1
    fi
}

verify_release_executor_blobs() {
    [ -n "$EXPECTED_RELEASE_COMMIT" ] || return 0
    local path expected actual
    for path in "${RELEASE_CRITICAL_EXECUTORS[@]}"; do
        if [ ! -f "$path" ] || [ -L "$path" ]; then
            echo "ERROR: critical release executor is missing, non-regular, or redirected: $path" >&2
            return 1
        fi
        expected=$($GIT_BIN rev-parse "$EXPECTED_RELEASE_COMMIT:$path" 2>/dev/null || true)
        actual=$($GIT_BIN hash-object --no-filters "$path" 2>/dev/null || true)
        if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
            echo "ERROR: critical release executor differs from the release commit: $path" >&2
            return 1
        fi
    done
}

verify_release_commit_binding() {
    [ -n "$EXPECTED_RELEASE_COMMIT" ] || return 0
    local source_tree metadata_tree parent_line diff_paths
    source_tree=$($GIT_BIN rev-parse "$EXPECTED_RELEASE_SOURCE_COMMIT^{tree}" 2>/dev/null || true)
    metadata_tree=$($GIT_BIN rev-parse "$EXPECTED_RELEASE_COMMIT^{tree}" 2>/dev/null || true)
    if [ "$source_tree" != "$EXPECTED_RELEASE_SOURCE_TREE" ] \
            || [ "$metadata_tree" != "$EXPECTED_RELEASE_METADATA_TREE" ]; then
        echo "ERROR: clean release CI source/metadata tree binding changed" >&2
        return 1
    fi
    if [ "$EXPECTED_RELEASE_COMMIT" = "$EXPECTED_RELEASE_SOURCE_COMMIT" ]; then
        [ "$EXPECTED_RELEASE_METADATA_TREE" = "$EXPECTED_RELEASE_SOURCE_TREE" ] || {
            echo "ERROR: metadata-free release does not retain its source tree" >&2
            return 1
        }
        return 0
    fi
    parent_line=$($GIT_BIN rev-list --parents -n 1 "$EXPECTED_RELEASE_COMMIT" 2>/dev/null || true)
    if [ "$parent_line" != "$EXPECTED_RELEASE_COMMIT $EXPECTED_RELEASE_SOURCE_COMMIT" ]; then
        echo "ERROR: clean release CI final commit is not the captured source's single child" >&2
        return 1
    fi
    diff_paths=$($GIT_BIN diff-tree --no-commit-id --name-only -r \
        "$EXPECTED_RELEASE_SOURCE_COMMIT" "$EXPECTED_RELEASE_COMMIT" | LC_ALL=C /usr/bin/sort)
    if [ "$diff_paths" != $'Casks/maccrab.rb\nhomebrew/maccrab.rb\nrelease.json' ]; then
        echo "ERROR: clean release CI metadata commit changed non-allowlisted paths" >&2
        printf '%s\n' "$diff_paths" >&2
        return 1
    fi
}

verify_release_source_snapshot() {
    [ -n "$EXPECTED_RELEASE_COMMIT" ] || return 0
    local actual_head dirty committed_hook_blob running_hook_blob
    reject_hidden_release_index_state
    verify_release_commit_binding
    verify_release_executor_blobs
    actual_head=$($GIT_BIN rev-parse HEAD 2>/dev/null || true)
    committed_hook_blob=$($GIT_BIN rev-parse "$EXPECTED_RELEASE_COMMIT:.githooks/pre-push" 2>/dev/null || true)
    running_hook_blob=$($GIT_BIN hash-object --no-filters .githooks/pre-push 2>/dev/null || true)
    dirty=$($GIT_BIN status --porcelain --untracked-files=all)
    if [ "$actual_head" != "$EXPECTED_RELEASE_COMMIT" ] \
            || [ -z "$committed_hook_blob" ] \
            || [ "$running_hook_blob" != "$committed_hook_blob" ] \
            || [ -n "$dirty" ]; then
        echo "ERROR: release source snapshot changed during clean CI" >&2
        echo "  expected commit: $EXPECTED_RELEASE_COMMIT" >&2
        echo "  actual HEAD:     ${actual_head:-<unreadable>}" >&2
        echo "  committed hook:  ${committed_hook_blob:-<unreadable>}" >&2
        echo "  executing hook:  ${running_hook_blob:-<unreadable>}" >&2
        if [ -n "$dirty" ]; then
            printf '%s\n' "$dirty" >&2
        fi
        return 1
    fi
}

verify_release_source_snapshot

if [ "$CLEAN_TREE" = "1" ]; then
    PRESERVED_RELEASE_DIR=""
    PRESERVED_RELEASE_COUNT=0
    PRESERVED_RELEASE_NAMES=()
    PRESERVED_RELEASE_SHAS=()

    release_artifact_sha() {
        /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
    }
    release_artifact_device() {
        /usr/bin/stat -f '%d' "$1"
    }
    is_nonempty_regular_release_artifact() {
        [ -f "$1" ] && [ ! -L "$1" ] && [ -s "$1" ]
    }
    restore_release_artifacts() {
        [ -n "$PRESERVED_RELEASE_DIR" ] || return 0
        if [ ! -d "$PRESERVED_RELEASE_DIR" ] || [ -L "$PRESERVED_RELEASE_DIR" ]; then
            echo "ERROR: release staging directory disappeared or was redirected: $PRESERVED_RELEASE_DIR" >&2
            return 1
        fi
        if [ -L .build ]; then
            echo "ERROR: refusing to restore release DMGs through symlink .build; originals remain at $PRESERVED_RELEASE_DIR" >&2
            return 1
        fi
        if [ -e .build ] && [ ! -d .build ]; then
            echo "ERROR: .build is not a directory; release DMGs remain recoverable at $PRESERVED_RELEASE_DIR" >&2
            return 1
        fi
        if ! mkdir -p .build; then
            echo "ERROR: cannot recreate .build; release DMG remains recoverable at $PRESERVED_RELEASE_DIR" >&2
            return 1
        fi
        if [ -L .build ] || [ ! -d .build ]; then
            echo "ERROR: .build changed type during restore; release DMGs remain at $PRESERVED_RELEASE_DIR" >&2
            return 1
        fi
        local build_device
        local staging_device
        if ! build_device=$(release_artifact_device .build) \
                || ! staging_device=$(release_artifact_device "$PRESERVED_RELEASE_DIR") \
                || [ "$build_device" != "$staging_device" ]; then
            echo "ERROR: release restore is not a same-filesystem rename; originals remain at $PRESERVED_RELEASE_DIR" >&2
            return 1
        fi

        # Validate every expected name and hash at its one legitimate location
        # before moving anything. A failed staging rename can leave both an
        # intact original and a partial destination; never overwrite the former.
        local index=0
        local staged_count=0
        local staged_path
        local restored_path
        local staged_sha
        local restored_sha
        local staged_valid
        local restored_valid
        local restore_flags=()
        while [ "$index" -lt "$PRESERVED_RELEASE_COUNT" ]; do
            staged_path="$PRESERVED_RELEASE_DIR/${PRESERVED_RELEASE_NAMES[$index]}"
            restored_path=".build/${PRESERVED_RELEASE_NAMES[$index]}"
            staged_valid=0
            restored_valid=0
            if [ -e "$staged_path" ] || [ -L "$staged_path" ]; then
                if ! is_nonempty_regular_release_artifact "$staged_path" \
                        || ! staged_sha=$(release_artifact_sha "$staged_path") \
                        || [ "$staged_sha" != "${PRESERVED_RELEASE_SHAS[$index]}" ]; then
                    echo "ERROR: staged release artifact is partial, redirected, or changed: $staged_path" >&2
                    return 1
                fi
                staged_valid=1
                staged_count=$((staged_count + 1))
            fi
            if [ -e "$restored_path" ] || [ -L "$restored_path" ]; then
                if ! is_nonempty_regular_release_artifact "$restored_path" \
                        || ! restored_sha=$(release_artifact_sha "$restored_path") \
                        || [ "$restored_sha" != "${PRESERVED_RELEASE_SHAS[$index]}" ]; then
                    echo "ERROR: restore destination already contains different or redirected bytes: $restored_path" >&2
                    return 1
                fi
                restored_valid=1
            fi
            if [ "$staged_valid" = "1" ] && [ "$restored_valid" = "1" ]; then
                echo "ERROR: refusing to overwrite an existing good artifact with a second copy: $restored_path" >&2
                return 1
            fi
            if [ "$staged_valid" = "0" ] && [ "$restored_valid" = "0" ]; then
                echo "ERROR: expected release artifact disappeared: ${PRESERVED_RELEASE_NAMES[$index]}" >&2
                return 1
            fi
            restore_flags[$index]=$staged_valid
            index=$((index + 1))
        done

        local actual_staged_count
        actual_staged_count=$(/usr/bin/find "$PRESERVED_RELEASE_DIR" -mindepth 1 -maxdepth 1 -print \
            | /usr/bin/wc -l | /usr/bin/tr -d ' ')
        if [ "$actual_staged_count" != "$staged_count" ]; then
            echo "ERROR: release staging directory contains an unowned or partial entry: $PRESERVED_RELEASE_DIR" >&2
            return 1
        fi

        index=0
        while [ "$index" -lt "$PRESERVED_RELEASE_COUNT" ]; do
            if [ "${restore_flags[$index]}" = "1" ]; then
                staged_path="$PRESERVED_RELEASE_DIR/${PRESERVED_RELEASE_NAMES[$index]}"
                restored_path=".build/${PRESERVED_RELEASE_NAMES[$index]}"
                if [ -L .build ] || [ ! -d .build ]; then
                    echo "ERROR: .build was redirected during restore; original remains at $staged_path" >&2
                    return 1
                fi
                if ! build_device=$(release_artifact_device .build) \
                        || [ "$build_device" != "$staging_device" ]; then
                    echo "ERROR: .build changed filesystem during restore; original remains at $staged_path" >&2
                    return 1
                fi
                if [ -e "$restored_path" ] || [ -L "$restored_path" ]; then
                    echo "ERROR: restore destination appeared during publication: $restored_path" >&2
                    return 1
                fi
                if ! /bin/mv -n "$staged_path" "$restored_path"; then
                    echo "ERROR: could not restore ${PRESERVED_RELEASE_NAMES[$index]}; staged original remains at $staged_path" >&2
                    return 1
                fi
                if [ -e "$staged_path" ] || [ -L "$staged_path" ] \
                        || ! is_nonempty_regular_release_artifact "$restored_path" \
                        || ! restored_sha=$(release_artifact_sha "$restored_path") \
                        || [ "$restored_sha" != "${PRESERVED_RELEASE_SHAS[$index]}" ]; then
                    echo "ERROR: restored release artifact failed postflight: $restored_path" >&2
                    return 1
                fi
            fi
            index=$((index + 1))
        done

        # Final whole-manifest postflight: every artifact must now exist only at
        # its real .build name with the exact pre-clean hash.
        if [ -L .build ] || [ ! -d .build ]; then
            echo "ERROR: .build was redirected after release-artifact restore" >&2
            return 1
        fi
        index=0
        while [ "$index" -lt "$PRESERVED_RELEASE_COUNT" ]; do
            staged_path="$PRESERVED_RELEASE_DIR/${PRESERVED_RELEASE_NAMES[$index]}"
            restored_path=".build/${PRESERVED_RELEASE_NAMES[$index]}"
            if [ -e "$staged_path" ] || [ -L "$staged_path" ] \
                    || ! is_nonempty_regular_release_artifact "$restored_path" \
                    || ! restored_sha=$(release_artifact_sha "$restored_path") \
                    || [ "$restored_sha" != "${PRESERVED_RELEASE_SHAS[$index]}" ]; then
                echo "ERROR: final release-artifact manifest postflight failed: $restored_path" >&2
                return 1
            fi
            index=$((index + 1))
        done
        if ! rmdir "$PRESERVED_RELEASE_DIR"; then
            echo "ERROR: release staging directory is not empty; inspect $PRESERVED_RELEASE_DIR" >&2
            return 1
        fi
        PRESERVED_RELEASE_DIR=""
        return 0
    }
    restore_release_artifacts_on_exit() {
        local status=$?
        trap - EXIT
        if ! restore_release_artifacts && [ "$status" -eq 0 ]; then
            status=1
        fi
        release_clean_lock_release
        exit "$status"
    }

    # Two concurrent --clean runs can destroy a notarized DMG, and the loss is
    # silent. Run A stages the artifact out of .build; run B then globs
    # .build/MacCrab-v*.dmg, finds nothing, sets PRESERVED_RELEASE_COUNT=0,
    # installs NO restore trap, and runs `rm -rf .build` — which deletes what A
    # restored. The realistic trigger is an operator, not an attacker: a tag push
    # while a manual clean run is still winding down. `mkdir` is the portable
    # atomic test-and-set here; macOS ships no flock(1).
    CLEAN_RELEASE_LOCK="$PROJECT_DIR/.maccrab-ci-clean.lock"
    release_clean_lock_held=0
    release_clean_lock_release() {
        [ "$release_clean_lock_held" = "1" ] || return 0
        release_clean_lock_held=0
        rm -rf "$CLEAN_RELEASE_LOCK"
    }
    release_clean_lock_claim() {
        if mkdir "$CLEAN_RELEASE_LOCK" 2>/dev/null; then
            release_clean_lock_held=1
            printf '%s\n' "$$" > "$CLEAN_RELEASE_LOCK/pid" 2>/dev/null || true
            return 0
        fi
        return 1
    }
    if ! release_clean_lock_claim; then
        lock_owner=$(cat "$CLEAN_RELEASE_LOCK/pid" 2>/dev/null || true)
        # Only a lock whose owner is provably gone may be broken, and only once.
        if [ -n "$lock_owner" ] && ! kill -0 "$lock_owner" 2>/dev/null; then
            echo "Clean run: clearing a stale release lock left by dead PID $lock_owner."
            rm -rf "$CLEAN_RELEASE_LOCK"
            release_clean_lock_claim || true
        fi
        if [ "$release_clean_lock_held" != "1" ]; then
            echo "ERROR: another clean CI run holds the release-artifact lock (PID ${lock_owner:-unknown})." >&2
            echo "       Running both would delete the preserved release DMG. Wait for it to" >&2
            echo "       finish, or remove $CLEAN_RELEASE_LOCK if you are certain it is stale." >&2
            exit 1
        fi
    fi
    trap 'release_clean_lock_release' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    if [ -L .build ]; then
        echo "ERROR: refusing clean CI with symlink .build" >&2
        exit 1
    fi
    if [ -e .build ] && [ ! -d .build ]; then
        echo "ERROR: refusing clean CI because .build is not a directory" >&2
        exit 1
    fi
    shopt -s nullglob
    release_artifacts=(.build/MacCrab-v*.dmg)
    shopt -u nullglob

    expected_index=0
    while [ "$expected_index" -lt "$EXPECTED_RELEASE_COUNT" ]; do
        expected_path=${EXPECTED_RELEASE_PATHS[$expected_index]}
        expected_sha=${EXPECTED_RELEASE_SHAS[$expected_index]}
        if ! is_nonempty_regular_release_artifact "$expected_path"; then
            echo "ERROR: required release DMG is missing, empty, non-regular, or a symlink: $expected_path" >&2
            exit 1
        fi
        actual_sha=$(release_artifact_sha "$expected_path")
        if [ "$actual_sha" != "$expected_sha" ]; then
            echo "ERROR: required release DMG changed before clean CI: $expected_path" >&2
            echo "  expected: $expected_sha" >&2
            echo "  actual:   $actual_sha" >&2
            exit 1
        fi
        expected_index=$((expected_index + 1))
    done

    if [ "${#release_artifacts[@]}" -gt 0 ]; then
        artifact_index=0
        for artifact in "${release_artifacts[@]}"; do
            if ! is_nonempty_regular_release_artifact "$artifact"; then
                echo "ERROR: release artifact is empty, non-regular, or a symlink: $artifact" >&2
                exit 1
            fi
            PRESERVED_RELEASE_NAMES[$artifact_index]=$(basename "$artifact")
            PRESERVED_RELEASE_SHAS[$artifact_index]=$(release_artifact_sha "$artifact")
            artifact_index=$((artifact_index + 1))
        done
        PRESERVED_RELEASE_COUNT=$artifact_index

        # Bind the preservation manifest back to the caller's pre-tag hashes.
        # A mutation between the first required-file check and manifest capture
        # must fail here, before any original pathname is moved.
        expected_index=0
        while [ "$expected_index" -lt "$EXPECTED_RELEASE_COUNT" ]; do
            expected_leaf=${EXPECTED_RELEASE_PATHS[$expected_index]#.build/}
            expected_found=0
            artifact_index=0
            while [ "$artifact_index" -lt "$PRESERVED_RELEASE_COUNT" ]; do
                if [ "${PRESERVED_RELEASE_NAMES[$artifact_index]}" = "$expected_leaf" ]; then
                    expected_found=1
                    if [ "${PRESERVED_RELEASE_SHAS[$artifact_index]}" \
                            != "${EXPECTED_RELEASE_SHAS[$expected_index]}" ]; then
                        echo "ERROR: required release DMG changed during manifest capture: ${EXPECTED_RELEASE_PATHS[$expected_index]}" >&2
                        exit 1
                    fi
                fi
                artifact_index=$((artifact_index + 1))
            done
            if [ "$expected_found" != "1" ]; then
                echo "ERROR: required release DMG is absent from the preservation manifest: ${EXPECTED_RELEASE_PATHS[$expected_index]}" >&2
                exit 1
            fi
            expected_index=$((expected_index + 1))
        done

        # A sibling of .build is guaranteed to share its filesystem. Requiring
        # matching st_dev makes every stage/restore operation a rename, never
        # mv's cross-device copy+delete fallback.
        PRESERVED_RELEASE_DIR=$(mktemp -d "$PROJECT_DIR/.maccrab-ci-release.XXXXXX")
        if ! chmod 700 "$PRESERVED_RELEASE_DIR"; then
            rmdir "$PRESERVED_RELEASE_DIR" || true
            PRESERVED_RELEASE_DIR=""
            echo "ERROR: could not make the release staging directory private" >&2
            exit 1
        fi
        build_device=$(release_artifact_device .build)
        staging_device=$(release_artifact_device "$PRESERVED_RELEASE_DIR")
        if [ "$build_device" != "$staging_device" ]; then
            rmdir "$PRESERVED_RELEASE_DIR"
            PRESERVED_RELEASE_DIR=""
            echo "ERROR: release staging directory is not on .build's filesystem" >&2
            exit 1
        fi
        trap restore_release_artifacts_on_exit EXIT
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        artifact_index=0
        while [ "$artifact_index" -lt "$PRESERVED_RELEASE_COUNT" ]; do
            artifact=".build/${PRESERVED_RELEASE_NAMES[$artifact_index]}"
            staged_artifact="$PRESERVED_RELEASE_DIR/${PRESERVED_RELEASE_NAMES[$artifact_index]}"
            if [ -L .build ] || [ ! -d .build ] \
                    || ! is_nonempty_regular_release_artifact "$artifact" \
                    || [ -e "$staged_artifact" ] || [ -L "$staged_artifact" ]; then
                echo "ERROR: release artifact changed before staging: $artifact" >&2
                exit 1
            fi
            actual_sha=$(release_artifact_sha "$artifact")
            if [ "$actual_sha" != "${PRESERVED_RELEASE_SHAS[$artifact_index]}" ]; then
                echo "ERROR: release artifact changed before staging: $artifact" >&2
                exit 1
            fi
            /bin/mv -n "$artifact" "$staged_artifact"
            if [ -e "$artifact" ] || [ -L "$artifact" ] \
                    || ! is_nonempty_regular_release_artifact "$staged_artifact"; then
                echo "ERROR: release artifact staging did not complete atomically: $artifact" >&2
                exit 1
            fi
            actual_sha=$(release_artifact_sha "$staged_artifact")
            if [ "$actual_sha" != "${PRESERVED_RELEASE_SHAS[$artifact_index]}" ]; then
                echo "ERROR: staged release artifact hash changed: $staged_artifact" >&2
                exit 1
            fi
            artifact_index=$((artifact_index + 1))
        done
        echo "Clean run: preserving $PRESERVED_RELEASE_COUNT release DMG(s) by same-filesystem rename at $PRESERVED_RELEASE_DIR."
    fi

    echo "Clean run: removing .build and re-resolving dependencies…"
    rm -rf .build
    swift package resolve
fi

# Never redirect CI output or compiler artifacts through fixed shared `/tmp`
# names. This script is the release gate on the signing Mac; a second local
# user can pre-create a predictable symlink/tree and turn an otherwise harmless
# check into an arbitrary-file clobber or stale-rules false green. `mktemp`
# creates private, per-run leaves below the invoking user's normal temp root.
CI_LOCAL_OUTPUT=$(mktemp "${TMPDIR:-/tmp}/maccrab-ci-output.XXXXXX")
# Per-run directory for the complete output of any gate that fails. Kept outside
# .build so a --clean wipe cannot destroy the evidence for the failure that
# stopped the release.
CI_FAILURE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/maccrab-ci-failures.XXXXXX")
CI_COMPILED_RULES=$(mktemp -d "${TMPDIR:-/tmp}/maccrab-ci-rules.XXXXXX")

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
START=$(date +%s)

check() {
    local name="$1"
    shift
    printf "  %-40s " "$name"
    if "$@" > "$CI_LOCAL_OUTPUT" 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC}"
        # Preserve the WHOLE failing gate, not just its tail. $CI_LOCAL_OUTPUT is
        # one reused buffer, so the next check() overwrote the evidence: an rc.8
        # release build failed here on a single test out of 4,116, and by the
        # time anyone looked, the only surviving record was five lines of
        # unrelated passing output from the end of the run. A gate that can fail
        # a release must leave something diagnosable behind — especially for a
        # flake, which by definition will not reproduce on demand.
        local slug
        slug=$(printf '%s' "$name" | LC_ALL=C tr -cs 'A-Za-z0-9' '-' | tr 'A-Z' 'a-z')
        slug=${slug#-}
        slug=${slug%-}
        local preserved="$CI_FAILURE_DIR/${slug:-gate}.log"
        if cp "$CI_LOCAL_OUTPUT" "$preserved" 2>/dev/null; then
            echo "    full output: $preserved"
        fi
        # Swift Testing prints one ✘ line per failing test; surface those
        # directly rather than whatever happened to run last.
        local failures
        failures=$(/usr/bin/grep -E '✘|recorded an issue|error:' "$CI_LOCAL_OUTPUT" 2>/dev/null | /usr/bin/head -12 || true)
        if [ -n "$failures" ]; then
            printf '%s\n' "$failures" | sed 's/^/    /'
        else
            tail -5 "$CI_LOCAL_OUTPUT" | sed 's/^/    /'
        fi
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo -e "${BOLD}MacCrab Local CI${NC}"
echo "════════════════════════════════════════"
echo ""

echo -e "${BOLD}Build${NC}"
check "Swift build (debug)" swift build
check "Swift build tests" swift build --build-tests

echo ""
echo -e "${BOLD}Tests${NC}"
check "Swift test suite" swift test --no-parallel

# README ships a green `tests-N passing` badge that NOTHING verified —
# prerelease-check.sh only printed it as info. It drifted badly: the badge said
# 3230, CLAUDE.md said 2642, and the suite actually ran 4109. On a product whose
# pitch is that its claims are checkable, an unchecked green badge is the wrong
# kind of decoration. The suite has just run and its summary is still in
# $CI_LOCAL_OUTPUT, so the true number is free to obtain — compare against the
# count that was actually executed, not against another hand-maintained file.
# Read it BEFORE the next check() overwrites the buffer.
OBSERVED_TEST_COUNT=$(/usr/bin/sed -n 's/.*Test run with \([0-9][0-9]*\) tests.*/\1/p' \
    "$CI_LOCAL_OUTPUT" | /usr/bin/tail -1)
assert_readme_tests_badge() {
    local observed="$1" badge
    if [ -z "$observed" ]; then
        echo "could not parse an executed test count from the suite output" >&2
        return 1
    fi
    badge=$(/usr/bin/grep -oE 'tests-[0-9]+%20passing' README.md \
        | /usr/bin/sed -E 's/tests-([0-9]+)%20passing/\1/' | /usr/bin/head -1)
    if [ -z "$badge" ]; then
        echo "README.md has no parseable tests badge" >&2
        return 1
    fi
    if [ "$badge" != "$observed" ]; then
        echo "README.md tests badge says $badge but the suite just ran $observed" >&2
        return 1
    fi
    echo "README tests badge agrees with the $observed tests just executed"
}
check "README tests badge matches suite" assert_readme_tests_badge "$OBSERVED_TEST_COUNT"

echo ""
echo -e "${BOLD}Rules${NC}"
# The compiler EXITS 0 even when it SKIPS a malformed rule, so a rule can drop
# out of the shipped corpus silently. The deleted ci.yml asserted
# `Rules skipped: 0`; nothing did after CI moved local — assert it here.
check "Compile rules (YAML → JSON)" env MACCRAB_CI_COMPILED_RULES="$CI_COMPILED_RULES" \
    bash -c 'out=$(python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir "$MACCRAB_CI_COMPILED_RULES") || exit 1; echo "$out"; echo "$out" | grep -qE "Rules skipped:[[:space:]]+0[[:space:]]*$"'
# make check-counts — headline rule-count drift across README / MODULES /
# ModuleStatus. Automated nowhere before this line.
check "Rule counts consistent (README/MODULES)" python3 scripts/coverage_matrix.py --check Rules
check "Rule lint (filter coverage)" ./scripts/rule-lint.sh
check "Rule trust-anchor adversarial fixture" ./scripts/test-rules-trust-anchor.sh

echo ""
echo -e "${BOLD}Required local gates${NC}"
# GitHub Actions was deliberately removed: hosted images cannot satisfy the
# pinned toolchain, and an untrusted-fork-capable self-hosted runner must not run
# on the signing Mac. This script and the version-controlled pre-push hook are
# the authoritative CI gate.
check "Broker fd fuzz (ASan/UBSan)" ./scripts/test-broker-fuzz.sh
check "Architectural audit (deterministic)" \
    env MACCRAB_AUDIT_SCOPE=deterministic ./scripts/pre-release-audit.sh
check "Release dependency provenance" ./scripts/check-release-dependencies.sh
check "Release supply-chain fixtures" ./scripts/test-release-supply-chain.sh
check "Installer/DMG payload fixtures" ./scripts/test-install-payload.sh
check "SQLCipher provenance fixtures" ./scripts/test-sqlcipher-provenance.sh

# Publication gate. `main` is public and dev squash-merges into it, so
# anything on dev is on a path to publication. Scans ADDED lines only —
# the repo legitimately contains ~100 credential-shaped strings (honeyfile
# canaries, sanitizer test fixtures) and a whole-tree scan reports all of
# them every run until someone switches it off.
check "No secrets or host paths in the diff" ./scripts/check-secrets.sh
check "Tag gate preserves release artifact" ./scripts/test-release-artifact-preservation.sh

echo ""
echo -e "${BOLD}Assessment harness (non-shipping sub-package)${NC}"
# Tools/AssessmentHarness is deliberately invisible to the root package, so
# `swift build` and `swift test` above never touch it. Before this block it was
# referenced by nothing in .github/workflows, this script, or the Makefile —
# the component that grades the detection engine was itself ungated, and could
# have stopped compiling without anyone noticing.
if [ "$CLEAN_TREE" = "1" ]; then
    # The harness is a nested package with its own ignored build directory.
    # Root `swift package resolve` does not clean it, so a release gate could
    # otherwise pass entirely on stale harness objects.
    /bin/rm -rf "$PROJECT_DIR/Tools/AssessmentHarness/.build"
fi
check "Harness builds" swift build --package-path Tools/AssessmentHarness
check "Harness tests" swift test --package-path Tools/AssessmentHarness
check "Harness stays out of the shipped build" ./Tools/AssessmentHarness/scripts/check-harness-isolation.sh

echo ""
echo -e "${BOLD}Code Quality${NC}"
check "No force unwraps in Sources" bash -c '! grep -rn "\.first!" Sources/ --include="*.swift" | grep -v ".build/" | grep -v "// OK:"'
check "No TODO/FIXME in Sources" bash -c 'count=$(grep -rn "TODO\|FIXME" Sources/ --include="*.swift" | grep -v ".build/" | wc -l); [ "$count" -lt 10 ]'

rm -f "$CI_LOCAL_OUTPUT"
rm -rf "$CI_COMPILED_RULES"

# Restore the release bytes before declaring the gate green, then prove the
# clean build did not move HEAD, alter a tracked/staged input, introduce an
# untracked input, or replace the version-controlled hook that is executing.
if [ "${PRESERVED_RELEASE_COUNT:-0}" -gt 0 ]; then
    restore_release_artifacts
    trap - EXIT HUP INT TERM
fi
verify_release_source_snapshot

END=$(date +%s)
DURATION=$((END - START))

echo ""
echo "════════════════════════════════════════"
echo -e "  ${GREEN}Passed:${NC} $PASS"
echo -e "  ${RED}Failed:${NC} $FAIL"
echo -e "  Time:   ${DURATION}s"
echo "════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n${RED}CI FAILED${NC}"
    exit 1
else
    echo -e "\n${GREEN}ALL CHECKS PASSED${NC}"
fi
