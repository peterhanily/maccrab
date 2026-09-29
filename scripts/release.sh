#!/bin/bash
# Disable tracing before any credential or private build-input expansion.
set +x
# release.sh — Two-phase exact-candidate build/qualification/publication flow
#
# Usage:
#   ./scripts/release.sh 1.1.0
#   ./scripts/release.sh 1.1.0 --resume-publish   # finish a release whose tag is
#                                                 # public but whose branch push failed;
#                                                 # run from a checkout of the tag's commit
#
# Requires: DEVELOPER_ID and NOTARIZE_KEYCHAIN_PROFILE for a new candidate.
# Set these in ~/.maccrab-release-env (parsed as data) or export them.
set -euo pipefail

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
SCRIPT_DIR="$(cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)"
PROJECT_DIR="$(/usr/bin/dirname "$SCRIPT_DIR")"
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
    GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE GIT_PREFIX GIT_CONFIG \
    GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM GIT_CONFIG_COUNT \
    GIT_CONFIG_PARAMETERS GIT_EXEC_PATH GIT_CEILING_DIRECTORIES \
    GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_SSH GIT_SSH_COMMAND GIT_PROXY_COMMAND
GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_REPLACE_OBJECTS
GIT_BIN=/usr/bin/git
SHASUM_BIN=/usr/bin/shasum
AWK_BIN=/usr/bin/awk
SED_BIN=/usr/bin/sed
GREP_BIN=/usr/bin/grep
TAR_BIN=/usr/bin/tar
CURL_BIN=/usr/bin/curl
GH_BIN=/opt/homebrew/bin/gh
CANONICAL_GH_REPO=peterhanily/maccrab
CANONICAL_GH_HOST=github.com
unset GH_REPO GH_HOST

cd "$PROJECT_DIR"

# BEGIN RELEASE_CRITICAL_EXECUTORS
RELEASE_CRITICAL_EXECUTORS=(
    .githooks/pre-push
    scripts/ci-local.sh
    scripts/run-ci-phase.py
    scripts/check-swift-toolchain.py
    scripts/ci-receipt.py
    scripts/release.sh
    scripts/build-release.sh
    scripts/prepare-dmg-payload.sh
    scripts/install.sh
    scripts/release-env.sh
    scripts/_release_env.py
    scripts/export-release-source.py
    scripts/candidate-qualification.py
    scripts/resource-baseline-provenance.py
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
    scripts/publish-site-release.sh
    scripts/publish-cask.sh
    Compiler/compile_rules.py
)
# END RELEASE_CRITICAL_EXECUTORS

reject_hidden_release_index_state() {
    local hidden
    hidden=$($GIT_BIN ls-files -v | $AWK_BIN 'substr($0,1,1) == "S" || substr($0,1,1) ~ /^[a-z]$/ { print }')
    if [ -n "$hidden" ]; then
        echo "ERROR: release index contains assume-unchanged/skip-worktree entries:" >&2
        printf '%s\n' "$hidden" >&2
        return 1
    fi
    if ! $GIT_BIN update-index --really-refresh >/dev/null 2>&1 \
            || ! $GIT_BIN diff-files --quiet -- \
            || ! $GIT_BIN diff-index --cached --quiet HEAD --; then
        echo "ERROR: release index/worktree differs from HEAD after a forced refresh" >&2
        return 1
    fi
}

verify_release_executor_blobs() {
    local commit="$1" path expected actual
    for path in "${RELEASE_CRITICAL_EXECUTORS[@]}"; do
        if [ ! -f "$path" ] || [ -L "$path" ]; then
            echo "ERROR: critical release executor is missing, non-regular, or redirected: $path" >&2
            return 1
        fi
        expected=$($GIT_BIN rev-parse "$commit:$path" 2>/dev/null || true)
        actual=$($GIT_BIN hash-object --no-filters "$path" 2>/dev/null || true)
        if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
            echo "ERROR: critical release executor does not match $commit: $path" >&2
            return 1
        fi
    done
}

require_clean_release_source() {
    local dirty input tracked_swiftpm
    reject_hidden_release_index_state
    dirty=$($GIT_BIN status --porcelain --untracked-files=all)
    if [ -n "$dirty" ]; then
        echo "ERROR: release source is not clean; tracked, staged, and untracked inputs must be committed first:" >&2
        printf '%s\n' "$dirty" >&2
        return 1
    fi
    tracked_swiftpm=$($GIT_BIN ls-files '.swiftpm/**' ':(glob)**/.swiftpm/**')
    if [ -n "$tracked_swiftpm" ]; then
        echo "ERROR: repository-local SwiftPM configuration must not be a release input:" >&2
        printf '%s\n' "$tracked_swiftpm" >&2
        return 1
    fi
    for input in \
        Xcode/Resources/MacCrabApp.entitlements \
        Xcode/Resources/MacCrabAgent.entitlements; do
        if ! $GIT_BIN ls-files --error-unmatch "$input" >/dev/null 2>&1; then
            echo "ERROR: shipped signing capability is not tracked: $input" >&2
            return 1
        fi
    done
}

if [ ! -x "$GIT_BIN" ] || [ ! -x "$SHASUM_BIN" ] \
        || [ ! -x "$AWK_BIN" ] || [ ! -x "$TAR_BIN" ]; then
    echo "ERROR: required fixed system release tools are unavailable" >&2
    exit 1
fi
require_clean_release_source
SOURCE_COMMIT=$($GIT_BIN rev-parse --verify 'HEAD^{commit}')
SOURCE_TREE=$($GIT_BIN rev-parse "$SOURCE_COMMIT^{tree}")
verify_release_executor_blobs "$SOURCE_COMMIT"

# Trusted parser library; ~/.maccrab-release-env is data, never shell code.
# shellcheck source=scripts/release-env.sh
source "$SCRIPT_DIR/release-env.sh"

# Capture caller-provided credentials as ordinary, unexported shell variables,
# then remove their public names from the environment before any CI, SwiftPM,
# package plugin, rule compiler, coverage tool, or unsigned assembly runs.
unset MACCRAB_CALLER_DEVELOPER_ID MACCRAB_CALLER_APPLE_ID \
    MACCRAB_CALLER_APPLE_TEAM_ID MACCRAB_CALLER_NOTARIZE_PASSWORD \
    MACCRAB_CALLER_NOTARIZE_KEYCHAIN_PROFILE MACCRAB_CALLER_GH_TOKEN \
    MACCRAB_CALLER_SITE_REPO_TOKEN MACCRAB_CALLER_TAP_REPO_TOKEN \
    MACCRAB_SIGN_DEVELOPER_ID MACCRAB_SIGN_APPLE_ID MACCRAB_SIGN_APPLE_TEAM_ID \
    MACCRAB_SIGN_NOTARIZE_PASSWORD MACCRAB_SIGN_NOTARIZE_KEYCHAIN_PROFILE \
    MACCRAB_PUBLISH_GH_TOKEN MACCRAB_PUBLISH_SITE_REPO_TOKEN \
    MACCRAB_PUBLISH_TAP_REPO_TOKEN
MACCRAB_CALLER_DEVELOPER_ID="${DEVELOPER_ID:-}"
MACCRAB_CALLER_APPLE_ID="${APPLE_ID:-}"
MACCRAB_CALLER_APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
MACCRAB_CALLER_NOTARIZE_PASSWORD="${NOTARIZE_PASSWORD:-}"
MACCRAB_CALLER_NOTARIZE_KEYCHAIN_PROFILE="${NOTARIZE_KEYCHAIN_PROFILE:-}"
MACCRAB_CALLER_GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
MACCRAB_CALLER_SITE_REPO_TOKEN="${SITE_REPO_TOKEN:-}"
MACCRAB_CALLER_TAP_REPO_TOKEN="${TAP_REPO_TOKEN:-}"
unset_maccrab_signing_env
unset_maccrab_publisher_env

VERSION=""
SKIP_PRERELEASE=0
PUBLISH_RC=0
# Seeded from the environment so the documented RUNTIME_REPORT/CONTAINMENT_REPORT
# overrides survive to the ${VAR:-default} application below; a flag still wins.
RUNTIME_REPORT="${RUNTIME_REPORT:-}"
CONTAINMENT_REPORT="${CONTAINMENT_REPORT:-}"
# Re-spinning a version used to die at `git tag` ("tag already exists") AFTER the
# full build + notarize had burnt ~15 minutes, leaving the release half-done with
# no way forward but manual surgery. --respin is the explicit opt-in to re-point
# an existing tag at the new HEAD.
RESPIN=0
# v1.22.2 pushed its verified tag, then the branch push failed and another
# change landed on origin's main, so main could no longer fast-forward to the
# tagged metadata commit. Every mode refused, and the operator merged by hand
# and ran the post-push steps manually. --resume-publish is that recovery:
# with origin's branch containing the tagged commit, it re-verifies the same
# qualified candidate and runs only the post-push publication, never moving or
# pushing the tag or the branch.
RESUME_PUBLISH=0
# The branch a release may be cut from. Nothing checked this: `git tag` tags HEAD
# of whatever branch is checked out and the script then pushed the `main` REF, so
# a release cut from `dev` (the day-to-day branch here) produced a tag pointing at
# a commit not reachable from the public default branch — and `gh release create`
# builds the release from that tag.
RELEASE_BRANCH="${RELEASE_BRANCH:-main}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-prerelease-check) SKIP_PRERELEASE=1; shift ;;
        --respin) RESPIN=1; shift ;;
        --resume-publish) RESUME_PUBLISH=1; shift ;;
        --publish-rc) PUBLISH_RC=1; shift ;;
        --runtime-report)
            [ "$#" -ge 2 ] || { echo "ERROR: --runtime-report requires a JSON path" >&2; exit 2; }
            RUNTIME_REPORT=$2
            shift 2
            ;;
        --containment-report)
            [ "$#" -ge 2 ] || { echo "ERROR: --containment-report requires a JSON path" >&2; exit 2; }
            CONTAINMENT_REPORT=$2
            shift 2
            ;;
        -*) echo "Unknown flag: $1"; exit 1 ;;
        *)
            [ -z "$VERSION" ] || { echo "ERROR: version may be supplied only once" >&2; exit 2; }
            VERSION=$1
            shift
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> [--publish-rc] [--skip-prerelease-check]"
    echo "          [--respin | --resume-publish]"
    echo "          [--runtime-report PATH] [--containment-report PATH]"
    echo "Example: $0 1.1.0"
    exit 1
fi
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
    echo "ERROR: version must be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-rc.N" >&2
    exit 2
fi
VERSION_IS_RC=0
if [[ "$VERSION" == *-rc.* ]]; then VERSION_IS_RC=1; fi
if [ "$VERSION_IS_RC" = "1" ] && [ "$PUBLISH_RC" != "1" ]; then
    echo "ERROR: release.sh will not put an RC on a public channel implicitly." >&2
    echo "For an unpublished candidate use:" >&2
    echo "  VERSION=$VERSION ALLOW_UNNOTARIZED=1 MACCRAB_BUILD_CHANNEL=dev ./scripts/build-release.sh" >&2
    echo "To publish an isolated GitHub prerelease only, re-run with --publish-rc." >&2
    exit 2
fi
if [ "$VERSION_IS_RC" != "1" ] && [ "$PUBLISH_RC" = "1" ]; then
    echo "ERROR: --publish-rc requires a -rc.N version" >&2
    exit 2
fi
if [ "$RESUME_PUBLISH" = "1" ] && [ "$RESPIN" = "1" ]; then
    echo "ERROR: --resume-publish publishes the existing tag; --respin replaces it. Choose one." >&2
    exit 2
fi

# Candidate qualification is local, host-specific evidence and is never
# committed. The public publisher accepts only the fixed candidate manifest
# emitted by this script's tracked-object build phase; callers may point at a
# runtime/containment report stored elsewhere, but no skip/override flag can
# disable their verification.
QUALIFICATION_DIR="$PROJECT_DIR/.qualification-evidence"
CANDIDATE_MANIFEST="$QUALIFICATION_DIR/MacCrab-v$VERSION.candidate.json"
RUNTIME_REPORT="${RUNTIME_REPORT:-$QUALIFICATION_DIR/MacCrab-v$VERSION.runtime.json}"
CONTAINMENT_REPORT="${CONTAINMENT_REPORT:-$QUALIFICATION_DIR/MacCrab-v$VERSION.containment.json}"
DMG_PATH=".build/MacCrab-v$VERSION.dmg"
CI_TRANSCRIPT=""
CI_STARTED_AT=""
CI_COMPLETED_AT=""

cd "$PROJECT_DIR"

ENV_FILE="$HOME/.maccrab-release-env"

load_signing_values() {
    unset_maccrab_signing_env
    if [ -e "$ENV_FILE" ] || [ -L "$ENV_FILE" ]; then
        load_maccrab_env_file signing "$ENV_FILE"
    fi
    [ -z "$MACCRAB_CALLER_DEVELOPER_ID" ] || DEVELOPER_ID="$MACCRAB_CALLER_DEVELOPER_ID"
    [ -z "$MACCRAB_CALLER_APPLE_ID" ] || APPLE_ID="$MACCRAB_CALLER_APPLE_ID"
    [ -z "$MACCRAB_CALLER_APPLE_TEAM_ID" ] || APPLE_TEAM_ID="$MACCRAB_CALLER_APPLE_TEAM_ID"
    [ -z "$MACCRAB_CALLER_NOTARIZE_PASSWORD" ] || NOTARIZE_PASSWORD="$MACCRAB_CALLER_NOTARIZE_PASSWORD"
    [ -z "$MACCRAB_CALLER_NOTARIZE_KEYCHAIN_PROFILE" ] \
        || NOTARIZE_KEYCHAIN_PROFILE="$MACCRAB_CALLER_NOTARIZE_KEYCHAIN_PROFILE"
    MACCRAB_SIGN_DEVELOPER_ID="${DEVELOPER_ID:-}"
    MACCRAB_SIGN_APPLE_ID="${APPLE_ID:-}"
    MACCRAB_SIGN_APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
    MACCRAB_SIGN_NOTARIZE_PASSWORD="${NOTARIZE_PASSWORD:-}"
    MACCRAB_SIGN_NOTARIZE_KEYCHAIN_PROFILE="${NOTARIZE_KEYCHAIN_PROFILE:-}"
    unset_maccrab_signing_env
}

load_publisher_values() {
    unset_maccrab_publisher_env
    if [ -e "$ENV_FILE" ] || [ -L "$ENV_FILE" ]; then
        load_maccrab_env_file publisher "$ENV_FILE"
    fi
    [ -z "$MACCRAB_CALLER_GH_TOKEN" ] || GH_TOKEN="$MACCRAB_CALLER_GH_TOKEN"
    [ -z "$MACCRAB_CALLER_SITE_REPO_TOKEN" ] || SITE_REPO_TOKEN="$MACCRAB_CALLER_SITE_REPO_TOKEN"
    [ -z "$MACCRAB_CALLER_TAP_REPO_TOKEN" ] || TAP_REPO_TOKEN="$MACCRAB_CALLER_TAP_REPO_TOKEN"

    # Prefer the credential Git already uses successfully for cross-repo
    # publication, but keep it unexported until one fixed publisher command.
    local git_pat
    git_pat=$(printf 'protocol=https\nhost=github.com\n\n' \
        | $GIT_BIN credential fill 2>/dev/null | $SED_BIN -n 's/^password=//p' || true)
    MACCRAB_PUBLISH_GH_TOKEN="${GH_TOKEN:-$git_pat}"
    MACCRAB_PUBLISH_SITE_REPO_TOKEN="${SITE_REPO_TOKEN:-$git_pat}"
    MACCRAB_PUBLISH_TAP_REPO_TOKEN="${TAP_REPO_TOKEN:-${SITE_REPO_TOKEN:-$git_pat}}"
    unset_maccrab_publisher_env
    unset git_pat
}

publisher_gh() {
    local family=${1:-}
    local subcommand
    shift || true
    case "$family" in
        api)
            set -- api --hostname "$CANONICAL_GH_HOST" "$@"
            ;;
        release)
            subcommand=${1:?gh release subcommand required}
            shift
            set -- release "$subcommand" --repo "$CANONICAL_GH_REPO" "$@"
            ;;
        *)
            echo "ERROR: unsupported GitHub CLI command family: $family" >&2
            return 2
            ;;
    esac
    if [ -n "$MACCRAB_PUBLISH_GH_TOKEN" ]; then
        GH_TOKEN="$MACCRAB_PUBLISH_GH_TOKEN" "$GH_BIN" "$@"
    else
        "$GH_BIN" "$@"
    fi
}

require_canonical_origin() {
    local origin_url
    origin_url=$($GIT_BIN remote get-url origin 2>/dev/null || true)
    case "$origin_url" in
        https://github.com/peterhanily/maccrab.git|git@github.com:peterhanily/maccrab.git)
            return 0 ;;
        *)
            echo "ERROR: origin is not the canonical MacCrab repository: ${origin_url:-<missing>}" >&2
            return 1 ;;
    esac
}

# release.sh relies on the version-controlled pre-push hook for the clean tag
# gate. Git does not activate repository hooks on clone, so merely having
# .githooks/pre-push in the tree is not enough: fail before build/tag work unless
# the hook Git will execute is this exact executable file.
VERSIONED_PRE_PUSH="$PROJECT_DIR/.githooks/pre-push"
require_versioned_pre_push_gate() {
    local configured_pre_push
    configured_pre_push=$($GIT_BIN rev-parse --git-path hooks/pre-push 2>/dev/null || true)
    case "$configured_pre_push" in
        /*) ;;
        *) configured_pre_push="$PROJECT_DIR/$configured_pre_push" ;;
    esac
    if [ ! -x "$VERSIONED_PRE_PUSH" ] \
            || [ ! -x "$configured_pre_push" ] \
            || [ ! "$configured_pre_push" -ef "$VERSIONED_PRE_PUSH" ]; then
        echo "ERROR: the versioned pre-push release gate is not configured/executable." >&2
        echo "Run 'make hooks' and verify 'git rev-parse --git-path hooks/pre-push'" >&2
        echo "resolves to $VERSIONED_PRE_PUSH before building or publishing a release." >&2
        return 1
    fi
}
require_versioned_pre_push_gate
current_branch=$($GIT_BIN symbolic-ref --short HEAD 2>/dev/null || echo "DETACHED")
# --resume-publish moves no local or remote ref and checks origin's branch
# itself. It runs from the published tag's own commit, usually a detached
# checkout, because the branch may since have changed files the qualification
# gate reads (checked below, before the gate).
if [ "$current_branch" != "$RELEASE_BRANCH" ] && [ "$RESUME_PUBLISH" != "1" ]; then
    echo "ERROR: on branch '$current_branch' but releases must be cut from '$RELEASE_BRANCH'." >&2
    exit 1
fi
require_clean_release_source
if [ "$($GIT_BIN rev-parse HEAD)" != "$SOURCE_COMMIT" ] \
        || [ "$($GIT_BIN rev-parse "$SOURCE_COMMIT^{tree}")" != "$SOURCE_TREE" ]; then
    echo "ERROR: release source commit/tree changed during preflight" >&2
    exit 1
fi
verify_release_executor_blobs "$SOURCE_COMMIT"

is_nonempty_regular_release_artifact() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ -s "$1" ]
}

is_regular_evidence_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ -s "$1" ]
}

# A published same-version tag is an earlier attempt of THIS candidate only when
# it names the source's single child changing exactly the GA metadata allowlist:
# the commit a release run creates just before its tag push.
is_release_metadata_child() {
    [ "$($GIT_BIN rev-list --parents -n 1 "$1")" = "$1 $SOURCE_COMMIT" ] \
        && [ "$($GIT_BIN diff-tree --no-commit-id --name-only -r "$SOURCE_COMMIT" "$1" \
            | LC_ALL=C /usr/bin/sort)" = $'Casks/maccrab.rb\nhomebrew/maccrab.rb\nrelease.json' ]
}

# Every recovery message prints this; an RC is refused without --publish-rc.
RESUME_COMMAND="scripts/release.sh $VERSION --resume-publish"
if [ "$VERSION_IS_RC" = "1" ]; then
    RESUME_COMMAND="scripts/release.sh $VERSION --publish-rc --resume-publish"
fi

# Under --resume-publish HEAD is the commit the published tag names, which for a
# GA is the metadata commit, not the qualified source. Take the source
# commit/tree from the candidate manifest instead; the qualification gate then
# verifies that manifest, the DMG's signed source attestation and both host
# reports against them exactly as it does for a normal second phase.
if [ "$RESUME_PUBLISH" = "1" ]; then
    if ! is_regular_evidence_file "$CANDIDATE_MANIFEST"; then
        echo "ERROR: --resume-publish needs the qualified candidate manifest: $CANDIDATE_MANIFEST" >&2
        exit 1
    fi
    manifest_source=$(/usr/bin/python3 -I -c '
import json, re, sys
candidate = json.load(open(sys.argv[1]))["candidate"]
object_id = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")
values = [candidate["source_commit"], candidate["source_tree"]]
if not all(isinstance(value, str) and object_id.fullmatch(value) for value in values):
    raise SystemExit(1)
print(*values)
' "$CANDIDATE_MANIFEST" 2>/dev/null || true)
    read -r SOURCE_COMMIT SOURCE_TREE <<< "$manifest_source"
    if [ -z "$SOURCE_COMMIT" ] || [ -z "$SOURCE_TREE" ] \
            || [ "$($GIT_BIN rev-parse --verify --quiet "$SOURCE_COMMIT^{commit}" || true)" != "$SOURCE_COMMIT" ] \
            || [ "$($GIT_BIN rev-parse --verify --quiet "$SOURCE_COMMIT^{tree}" || true)" != "$SOURCE_TREE" ]; then
        echo "ERROR: the candidate manifest does not name a local source commit and its tree: $CANDIDATE_MANIFEST" >&2
        exit 1
    fi
    echo "Resume: qualified candidate source $SOURCE_COMMIT (checkout HEAD $($GIT_BIN rev-parse HEAD))"
    # The gate re-reads this checkout, not the source commit: it compares the
    # rule corpus, the runtime workload executors, the committed resource
    # baseline and the Tier-B containment sources with the evidence recorded
    # for the source, and the containment evidence names this directory. The
    # v1.22.2 recovery merged main before publishing, and a merge checkout
    # carrying a later rule edit fails that gate with no hint why. Require the
    # tag's own commit, which matches the source in every file except
    # release.json and the casks, and check it here, before the gate runs.
    resume_head=$($GIT_BIN rev-parse HEAD)
    if { [ "$VERSION_IS_RC" = "1" ] && [ "$resume_head" != "$SOURCE_COMMIT" ]; } \
            || { [ "$VERSION_IS_RC" != "1" ] && ! is_release_metadata_child "$resume_head"; }; then
        if [ "$VERSION_IS_RC" = "1" ]; then
            echo "ERROR: --resume-publish of an RC runs from its qualified source $SOURCE_COMMIT," >&2
        else
            echo "ERROR: --resume-publish runs from the commit v$VERSION names: the single child of" >&2
            echo "       the qualified source $SOURCE_COMMIT changing exactly release.json and both casks," >&2
        fi
        echo "       but this checkout is $resume_head. The qualification gate re-reads this" >&2
        echo "       checkout's rules, workload scripts, resource baseline and containment" >&2
        echo "       sources, so a later commit can fail it. In this same directory, which" >&2
        echo "       holds the candidate and its evidence, run:" >&2
        echo "         git fetch origin tag v$VERSION" >&2
        echo "         git checkout --detach v$VERSION" >&2
        echo "         $RESUME_COMMAND" >&2
        echo "       Nothing was published, and no tag or branch was moved." >&2
        exit 1
    fi
    # The gate and every executor below are then the ones this candidate was
    # qualified with, not whatever a later commit carries.
    verify_release_executor_blobs "$SOURCE_COMMIT"
fi
BUILD_NUMBER="${VERSION%%-rc.*}.$($GIT_BIN rev-list --count "$SOURCE_COMMIT")"

run_candidate_qualification_gate() {
    /usr/bin/python3 -I "$SCRIPT_DIR/candidate-qualification.py" verify-release \
        --version "$VERSION" \
        --build-number "$BUILD_NUMBER" \
        --source-commit "$SOURCE_COMMIT" \
        --source-tree "$SOURCE_TREE" \
        --source-root "$PROJECT_DIR" \
        --dmg "$PROJECT_DIR/$DMG_PATH" \
        --candidate-manifest "$CANDIDATE_MANIFEST" \
        --runtime-report "$RUNTIME_REPORT" \
        --containment-report "$CONTAINMENT_REPORT"
}

print_qualification_next_steps() {
    echo "" >&2
    echo "PUBLICATION STOPPED: the exact candidate has not completed its installed-host gates." >&2
    echo "No tag, branch push, GitHub draft, release, appcast, or cask was changed." >&2
    echo "" >&2
    echo "Candidate:   $PROJECT_DIR/$DMG_PATH" >&2
    echo "Manifest:    $CANDIDATE_MANIFEST" >&2
    echo "Runtime:     $RUNTIME_REPORT" >&2
    echo "Containment: $CONTAINMENT_REPORT" >&2
    echo "" >&2
    echo "1. Install this exact DMG, keep ordinary browser/terminal/dashboard work active," >&2
    echo "   then run the root-owned recorder (it performs the fixed burst + reload):" >&2
    echo "   sudo /usr/bin/python3 -I scripts/candidate-qualification.py record-runtime \\" >&2
    echo "     --candidate-manifest '$CANDIDATE_MANIFEST' \\" >&2
    echo "     --dmg '$PROJECT_DIR/$DMG_PATH' --source-root '$PROJECT_DIR' \\" >&2
    echo "     --output '$RUNTIME_REPORT'" >&2
    # v1.22.2: a fresh clone ran the whole 900 s epoch before discovering this
    # gitignored receipt was missing. Say so before the operator starts.
    local baseline_sha baseline_path
    baseline_sha=$($GIT_BIN show "$SOURCE_COMMIT:docs/RELEASE_RESOURCE_BASELINE.json" 2>/dev/null \
        | /usr/bin/python3 -I -c 'import json, sys; print(json.load(sys.stdin)["private_evidence"]["sha256"])' \
            2>/dev/null || true)
    baseline_path="$PROJECT_DIR/.qualification-evidence/resource-baseline/${baseline_sha:-<private_evidence.sha256>}.json"
    echo "   It requires the private resource baseline committed to by" >&2
    echo "   docs/RELEASE_RESOURCE_BASELINE.json, which Git never carries:" >&2
    if [ -n "$baseline_sha" ] && [ -f "$baseline_path" ] && [ ! -L "$baseline_path" ]; then
        echo "     $baseline_path (present)" >&2
    else
        echo "     $baseline_path (MISSING)" >&2
    fi
    echo "   In a fresh clone, copy it from the reference checkout with its permissions" >&2
    echo "   (directory 0700, file 0600, owned by you)." >&2
    echo "2. Run 'VERSION=$VERSION make test-corpus' for the on-device containment JSON." >&2
    echo "3. Re-run this same release command. It will reuse, rehash, and re-verify" >&2
    echo "   these exact candidate bytes; it will not rebuild them." >&2
}

CANDIDATE_READY=0
QUALIFIED_CANDIDATE_SHA=""
QUALIFIED_MANIFEST_SHA=""
QUALIFIED_RUNTIME_SHA=""
QUALIFIED_CONTAINMENT_SHA=""
if is_nonempty_regular_release_artifact "$DMG_PATH"; then
    if ! is_regular_evidence_file "$CANDIDATE_MANIFEST"; then
        echo "ERROR: $DMG_PATH exists but has no trusted candidate manifest." >&2
        echo "It may have come from the standalone build-only workflow and cannot be published." >&2
        echo "Move it aside, then rerun release.sh to build a tracked-object candidate." >&2
        exit 3
    fi
    if ! is_regular_evidence_file "$RUNTIME_REPORT" \
            || ! is_regular_evidence_file "$CONTAINMENT_REPORT"; then
        print_qualification_next_steps
        exit 3
    fi
    echo "Qualification preflight: verifying preserved candidate and installed-host evidence..."
    run_candidate_qualification_gate || {
        echo "ERROR: candidate qualification failed. The preserved DMG will not be rebuilt or published." >&2
        exit 1
    }
    CANDIDATE_READY=1
    QUALIFIED_CANDIDATE_SHA=$($SHASUM_BIN -a 256 "$DMG_PATH" | $AWK_BIN '{print $1}')
    QUALIFIED_MANIFEST_SHA=$($SHASUM_BIN -a 256 "$CANDIDATE_MANIFEST" | $AWK_BIN '{print $1}')
    QUALIFIED_RUNTIME_SHA=$($SHASUM_BIN -a 256 "$RUNTIME_REPORT" | $AWK_BIN '{print $1}')
    QUALIFIED_CONTAINMENT_SHA=$($SHASUM_BIN -a 256 "$CONTAINMENT_REPORT" | $AWK_BIN '{print $1}')
elif [ -e "$DMG_PATH" ] || [ -L "$DMG_PATH" ]; then
    echo "ERROR: candidate path is empty, non-regular, or redirected: $DMG_PATH" >&2
    exit 1
elif [ -e "$CANDIDATE_MANIFEST" ] || [ -L "$CANDIDATE_MANIFEST" ] \
        || [ -e "$RUNTIME_REPORT" ] || [ -L "$RUNTIME_REPORT" ]; then
    echo "ERROR: candidate/runtime evidence exists but the exact DMG is missing: $DMG_PATH" >&2
    echo "Refusing to let stale evidence qualify rebuilt bytes." >&2
    exit 1
fi

assert_qualification_evidence_unchanged() {
    [ "$CANDIDATE_READY" = "1" ] || return 1
    local stage="${1:-qualification recheck}"
    local current_candidate current_manifest current_runtime current_containment
    if ! is_nonempty_regular_release_artifact "$DMG_PATH"; then
        if [ "$stage" = "branch push" ]; then
            echo "ERROR: Release artifact disappeared, became empty/non-regular, or was redirected during the push/CI gate: $DMG_PATH" >&2
            echo "The verified tag is already remote; stop before moving the release branch or creating a GitHub release." >&2
        else
            echo "ERROR: qualification evidence disappeared or changed type: $DMG_PATH" >&2
        fi
        return 1
    fi
    for evidence_path in "$CANDIDATE_MANIFEST" "$RUNTIME_REPORT" "$CONTAINMENT_REPORT"; do
        is_regular_evidence_file "$evidence_path" || {
            echo "ERROR: qualification evidence disappeared or changed type: $evidence_path" >&2
            return 1
        }
    done
    current_candidate=$($SHASUM_BIN -a 256 "$DMG_PATH" | $AWK_BIN '{print $1}')
    current_manifest=$($SHASUM_BIN -a 256 "$CANDIDATE_MANIFEST" | $AWK_BIN '{print $1}')
    current_runtime=$($SHASUM_BIN -a 256 "$RUNTIME_REPORT" | $AWK_BIN '{print $1}')
    current_containment=$($SHASUM_BIN -a 256 "$CONTAINMENT_REPORT" | $AWK_BIN '{print $1}')
    if [ "$current_candidate" != "$QUALIFIED_CANDIDATE_SHA" ]; then
        if [ "$stage" = "branch push" ]; then
            echo "ERROR: Release artifact changed during the push/CI gate." >&2
            echo "The verified tag is already remote; stop before moving the release branch or creating a GitHub release." >&2
        else
            echo "ERROR: exact candidate changed after qualification" >&2
        fi
        return 1
    fi
    if [ "$current_manifest" != "$QUALIFIED_MANIFEST_SHA" ] \
            || [ "$current_runtime" != "$QUALIFIED_RUNTIME_SHA" ] \
            || [ "$current_containment" != "$QUALIFIED_CONTAINMENT_SHA" ]; then
        echo "ERROR: exact candidate report evidence changed after validation" >&2
        return 1
    fi
}

# Post-publish failures used to be logged and swallowed: each of Steps 6 / 6b /
# 6c / 6d printed "! ... failed, run it manually" and the script still ended with
# "MacCrab v$VERSION Released!" and exit 0. That is how a release can ship while
# https://maccrab.com/release.json still advertises the PREVIOUS version, its
# DMG sha256 and its test counts — the publish soft-failed, nothing ever re-read
# the LIVE file, and the release was declared successful.
#
# Collect failures here and fail the whole release at the END rather than at the
# point of failure: a dead SITE_REPO_TOKEN must not also strand the tap cask
# (Step 6d) or the appcast. Every remaining publish step still gets its chance;
# the script just refuses to call the release good.
RELEASE_FAILURES=""
RELEASE_FAILURE_COUNT=0
release_fail() {
    RELEASE_FAILURE_COUNT=$(( RELEASE_FAILURE_COUNT + 1 ))
    RELEASE_FAILURES="${RELEASE_FAILURES}    - $1"$'\n'
    echo "  ✗ $1" >&2
}

# An accepted resource baseline must already be part of the source commit.
# Reject an unqualifiable first-phase artifact before CI, signing or Apple upload.
if [ "$CANDIDATE_READY" != "1" ]; then
    /usr/bin/python3 -I -B - "$SCRIPT_DIR/candidate-qualification.py" \
        "$PROJECT_DIR" "$SOURCE_COMMIT" <<'PYTHON'
import pathlib
import runpy
import sys

qualification = runpy.run_path(sys.argv[1])
try:
    qualification["release_resource_limits"](pathlib.Path(sys.argv[2]), sys.argv[3])
except qualification["QualificationError"] as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    raise SystemExit(1)
PYTHON
fi

# A first-phase candidate build needs the signing/notary projection but must not
# touch publisher credentials or GitHub. A second-phase publication reuses
# already signed/notarized bytes and therefore does not need Apple credentials.
load_signing_values
if [ "$CANDIDATE_READY" != "1" ] && [ -z "$MACCRAB_SIGN_DEVELOPER_ID" ]; then
    echo "ERROR: DEVELOPER_ID not set."
    echo ""
    echo "Either export it or create ~/.maccrab-release-env with:"
    echo '  export DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"'
    echo '  export NOTARIZE_KEYCHAIN_PROFILE="maccrab-notary"'
    echo 'Create that profile interactively: xcrun notarytool store-credentials maccrab-notary'
    echo 'Enter credentials at the prompts, never in command arguments.'
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  MacCrab v$VERSION Release                       "
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Remote release state is read here, before Step 0. Each check is seconds of
# read-only Git against origin and decides whether this run can ever publish;
# they used to run after the ~30-minute clean CI, so a refusal cost the whole
# gate. The tag push re-reads origin immediately before it goes out.

# The branch push after the tag push is a plain, non-force push of the release
# commit (the source's metadata child, or the source itself for an RC), so it
# lands only when origin's branch is an ancestor of the source. v1.22.2's did
# not: another change reached main first and left a public tag main could not
# reach. Sets origin_branch_commit for the caller's diagnosis.
origin_branch_commit=""
origin_release_branch_fast_forwards() {
    origin_branch_commit=$($GIT_BIN ls-remote origin "refs/heads/$RELEASE_BRANCH" \
        | $AWK_BIN -v ref="refs/heads/$RELEASE_BRANCH" '$2 == ref && !found { print $1; found = 1 }')
    [ -n "$origin_branch_commit" ] \
        && $GIT_BIN rev-parse --verify --quiet "${origin_branch_commit}^{commit}" >/dev/null \
        && $GIT_BIN merge-base --is-ancestor "$origin_branch_commit" "$SOURCE_COMMIT"
}

# --resume-publish instead needs origin's branch to CONTAIN the tagged release
# commit, as it would after a successful branch push (or the operator's merge).
# The branch's objects are fetched, writing no ref, when they are not local.
origin_release_branch_contains() {
    origin_branch_commit=$($GIT_BIN ls-remote origin "refs/heads/$RELEASE_BRANCH" \
        | $AWK_BIN -v ref="refs/heads/$RELEASE_BRANCH" '$2 == ref && !found { print $1; found = 1 }')
    [ -n "$origin_branch_commit" ] || return 1
    if ! $GIT_BIN cat-file -e "${origin_branch_commit}^{commit}" 2>/dev/null \
            && ! $GIT_BIN fetch --quiet --no-tags --no-prune --no-write-fetch-head \
                origin "refs/heads/$RELEASE_BRANCH"; then
        echo "ERROR: could not fetch origin's $RELEASE_BRANCH ($origin_branch_commit) to check it" >&2
        exit 1
    fi
    $GIT_BIN merge-base --is-ancestor "$1" "$origin_branch_commit"
}

echo "Remote preflight: origin's release tags and $RELEASE_BRANCH..."
require_canonical_origin
published_tag_refs=$($GIT_BIN ls-remote --tags origin 'refs/tags/v*')
published_tags=$(printf '%s\n' "$published_tag_refs" \
    | $AWK_BIN '{ print $2 }' \
    | /usr/bin/sed -e 's|^refs/tags/||' -e 's|\^{}$||' \
    | LC_ALL=C /usr/bin/sort -u)
release_tag_object=$(printf '%s\n' "$published_tag_refs" \
    | $AWK_BIN -v ref="refs/tags/v$VERSION" '$2 == ref && !found { print $1; found = 1 }')
release_tag_commit=""
release_tag_is_metadata_child=0
if [ -n "$release_tag_object" ]; then
    # v1.22.2's operator had deleted the local tag, so --respin could not even
    # resolve origin's. --respin and --resume-publish fetch only that tag when
    # its objects are absent; a plain run refuses a published version anyway.
    if ! $GIT_BIN cat-file -e "$release_tag_object" 2>/dev/null \
            && { [ "$RESPIN" = "1" ] || [ "$RESUME_PUBLISH" = "1" ]; }; then
        echo "  Fetching published tag v$VERSION to check what it names"
        if ! $GIT_BIN fetch --quiet --no-tags --no-prune --no-write-fetch-head \
                origin "refs/tags/v$VERSION"; then
            echo "ERROR: could not fetch published tag v$VERSION to check its ancestry" >&2
            exit 1
        fi
    fi
    release_tag_commit=$($GIT_BIN rev-parse --verify --quiet "${release_tag_object}^{commit}" || true)
    if [ -n "$release_tag_commit" ] && is_release_metadata_child "$release_tag_commit"; then
        release_tag_is_metadata_child=1
    fi
fi

# The tag push is leased to exactly this value: a replaceable earlier attempt
# under --respin, otherwise empty, meaning v$VERSION must not exist on origin.
tag_push_lease_object=""
if [ "$RESUME_PUBLISH" = "1" ]; then
    if [ -z "$release_tag_object" ]; then
        echo "ERROR: origin has no v$VERSION tag, so there is no publication to resume." >&2
        echo "       Run the release without --resume-publish." >&2
        exit 1
    fi
    if [ "$($GIT_BIN cat-file -t "$release_tag_object" 2>/dev/null || true)" != "tag" ] \
            || [ "$($GIT_BIN cat-file tag "$release_tag_object" | $SED_BIN -n 's/^tag //p' \
                | /usr/bin/head -1)" != "v$VERSION" ]; then
        echo "ERROR: published v$VERSION ($release_tag_object) is not an annotated tag named" >&2
        echo "       v$VERSION. release.sh creates only annotated tags; this is not its publication." >&2
        exit 1
    fi
    if [ "$VERSION_IS_RC" = "1" ]; then
        # An RC is published from the exact source commit, with no metadata commit.
        if [ "$release_tag_commit" != "$SOURCE_COMMIT" ]; then
            echo "ERROR: published v$VERSION names ${release_tag_commit:-<unresolved>}, not the" >&2
            echo "       qualified RC source $SOURCE_COMMIT; refusing to publish this candidate under it." >&2
            exit 1
        fi
    else
        if [ "$release_tag_is_metadata_child" != "1" ]; then
            echo "ERROR: published v$VERSION names ${release_tag_commit:-<unresolved>}, which is not the" >&2
            echo "       single child of the qualified source $SOURCE_COMMIT changing exactly" >&2
            echo "       release.json and both casks. --resume-publish finishes only the" >&2
            echo "       metadata commit a release run of this candidate pushed." >&2
            exit 1
        fi
        # The check before the gate proved HEAD matches the source in every
        # file the gate reads. A re-spin can leave more than one metadata
        # commit, so also bind HEAD to the one origin's tag names. (An RC's
        # HEAD and tag were both checked against the source itself.)
        if [ "$release_tag_commit" != "$resume_head" ]; then
            echo "ERROR: published v$VERSION names $release_tag_commit, but this checkout is" >&2
            echo "       $resume_head. Run --resume-publish from the tag's commit, in this directory:" >&2
            echo "         git checkout --detach $release_tag_commit" >&2
            echo "         $RESUME_COMMAND" >&2
            echo "       Nothing was published, and no tag or branch was moved." >&2
            exit 1
        fi
        for metadata_path in release.json Casks/maccrab.rb homebrew/maccrab.rb; do
            case "$metadata_path" in
                release.json) metadata_sha_pattern='"sha256"[[:space:]]*:[[:space:]]*"[a-f0-9]{64}"' ;;
                *) metadata_sha_pattern='sha256[[:space:]]+"[a-f0-9]{64}"' ;;
            esac
            metadata_sha=$($GIT_BIN cat-file blob "$release_tag_commit:$metadata_path" 2>/dev/null \
                | $GREP_BIN -oE "$metadata_sha_pattern" | /usr/bin/head -1 \
                | $GREP_BIN -oE '[a-f0-9]{64}' || true)
            if [ "$metadata_sha" != "$QUALIFIED_CANDIDATE_SHA" ]; then
                echo "ERROR: $metadata_path in published v$VERSION names ${metadata_sha:-<no sha256>}," >&2
                echo "       not the qualified DMG $QUALIFIED_CANDIDATE_SHA." >&2
                exit 1
            fi
        done
    fi
    if ! origin_release_branch_contains "$release_tag_commit"; then
        echo "ERROR: origin's $RELEASE_BRANCH (${origin_branch_commit:-<missing>}) does not contain" >&2
        echo "       $release_tag_commit, the commit published v$VERSION names, so the" >&2
        echo "       release would announce a commit $RELEASE_BRANCH cannot reach." >&2
        echo "       Merge it into $RELEASE_BRANCH, never squash, rebase or cherry-pick it (each" >&2
        echo "       makes a different commit and leaves the tag unreachable), and push. Then" >&2
        echo "       return to the tag's commit, because the qualification gate re-reads this" >&2
        echo "       checkout and the merge can bring in later rule or workload changes, and rerun:" >&2
        echo "         git fetch origin" >&2
        echo "         git switch $RELEASE_BRANCH" >&2
        echo "         git merge origin/$RELEASE_BRANCH" >&2
        echo "         git merge $release_tag_commit" >&2
        echo "         git push origin $RELEASE_BRANCH" >&2
        echo "         git checkout --detach $release_tag_commit" >&2
        echo "         $RESUME_COMMAND" >&2
        echo "       Nothing was published, and no tag or branch was moved." >&2
        exit 1
    fi
    echo "  ✓ Resume: v$VERSION is annotated tag $release_tag_object on ${release_tag_commit:0:12}," \
        "which origin's $RELEASE_BRANCH contains"
elif [ -n "$release_tag_object" ] && [ "$RESPIN" = "1" ]; then
    # Only a proven earlier attempt of this candidate may be replaced: its
    # commit count is the one this run publishes, so replacing it cannot
    # regress CFBundleVersion. A tag on the source itself or an ancestor used
    # to pass the ancestry loop below and was then force-replaced.
    if [ "$release_tag_is_metadata_child" != "1" ]; then
        echo "ERROR: --respin will not replace published v$VERSION ($release_tag_object," >&2
        echo "       commit ${release_tag_commit:-<unresolved>})." >&2
        echo "       --respin replaces v$VERSION only when it names this source's single" >&2
        echo "       child changing exactly release.json and both casks; this tag does not." >&2
        echo "       A published tag on any other commit is a real release: bump the version." >&2
        exit 1
    fi
    tag_push_lease_object=$release_tag_object
    echo "  Re-spin: published v$VERSION is this source's earlier metadata commit" \
        "(${release_tag_commit:0:12}); it will be replaced"
elif [ -n "$release_tag_commit" ]; then
    if [ "$release_tag_is_metadata_child" = "1" ]; then
        # Advice to merge and re-cut would produce a new source and throw away
        # the qualified candidate this tag already describes.
        echo "ERROR: v$VERSION is already published on origin, on this source's metadata commit" >&2
        echo "       $release_tag_commit: an earlier run of this candidate pushed its tag and" >&2
        echo "       stopped before publishing, as v1.22.2 did when its branch push failed." >&2
        echo "       Publish that tag without rebuilding, from its commit in this directory:" >&2
        echo "         git checkout --detach $release_tag_commit" >&2
        echo "         $RESUME_COMMAND" >&2
        echo "       It explains how to merge the tag's commit if origin's $RELEASE_BRANCH lacks it." >&2
        if origin_release_branch_fast_forwards; then
            echo "       Or, because origin's $RELEASE_BRANCH has not moved past this source," >&2
            echo "       --respin can replace the tag with a new metadata commit." >&2
        fi
    else
        echo "ERROR: v$VERSION is already published on origin (commit $release_tag_commit)." >&2
        echo "       A release run creates its tag and cannot replace a published one; bump the version." >&2
    fi
    exit 1
fi

# `rev-list --count` is monotonic only along ONE ancestry, and nothing used to
# check that this release shares it. A release cut from a branch that
# squash-merged the qualified work carries a LOWER count than the candidate that
# was actually tested, and Sparkle compares CFBundleVersion: every tester on the
# higher candidate build would be told they are current and never offered the
# shipped release. Enforce the property the derivation assumes — this commit
# must descend from every release already published — rather than hoping for it.
while IFS= read -r prior_tag; do
    [ -n "$prior_tag" ] || continue
    # This release's own tag was judged above: resumed or proven replaceable.
    if [ "$prior_tag" = "v$VERSION" ] \
            && { [ "$RESUME_PUBLISH" = "1" ] || [ -n "$tag_push_lease_object" ]; }; then
        continue
    fi
    prior_commit=$($GIT_BIN rev-parse --verify --quiet "refs/tags/${prior_tag}^{commit}" || true)
    if [ -z "$prior_commit" ]; then
        echo "ERROR: published tag '$prior_tag' is not present locally, so its ancestry" >&2
        echo "       cannot be checked. Run: git fetch --tags origin" >&2
        exit 1
    fi
    if ! $GIT_BIN merge-base --is-ancestor "$prior_commit" "$SOURCE_COMMIT"; then
        echo "ERROR: release source $SOURCE_COMMIT does not descend from published tag" >&2
        echo "       $prior_tag ($prior_commit)." >&2
        echo "       CFBundleVersion is derived from the commit count, so this build could" >&2
        echo "       publish a version BELOW one already released — Sparkle would then never" >&2
        echo "       offer it to anyone running the higher build. Merge (do NOT squash) the" >&2
        echo "       published history into this branch and re-cut." >&2
        exit 1
    fi
done <<PUBLISHED_TAGS
$published_tags
PUBLISHED_TAGS
echo "  ✓ Descends from every published release tag (commit count cannot regress)"

if [ "$RESUME_PUBLISH" != "1" ]; then
    if ! origin_release_branch_fast_forwards; then
        if [ -n "$tag_push_lease_object" ]; then
            # By v1.22.2's recovery, origin/main had taken PR #8, which the
            # source does not contain. Re-spinning then would force the public
            # tag onto a new metadata commit and fail the branch push again.
            echo "ERROR: --respin would replace published v$VERSION, but origin's $RELEASE_BRANCH" >&2
            echo "       (${origin_branch_commit:-<missing>}) is not an ancestor of source $SOURCE_COMMIT." >&2
            echo "       The branch push after the tag push could not fast-forward, leaving the" >&2
            echo "       replaced public tag on a commit $RELEASE_BRANCH cannot reach." >&2
            echo "       Do not re-spin. Publish the existing tag instead: make origin's" >&2
            echo "       $RELEASE_BRANCH contain $release_tag_commit (merge it; never squash or" >&2
            echo "       rebase), then run from that commit, in this directory:" >&2
            echo "         git checkout --detach $release_tag_commit" >&2
            echo "         $RESUME_COMMAND" >&2
        else
            echo "ERROR: origin's $RELEASE_BRANCH (${origin_branch_commit:-<missing>}) is not an ancestor" >&2
            echo "       of source $SOURCE_COMMIT, so the branch push after the tag push could not" >&2
            echo "       fast-forward and the public tag would name a commit $RELEASE_BRANCH cannot" >&2
            echo "       reach, as v1.22.2's did. No CI ran and nothing was tagged or pushed." >&2
            echo "       Merge (never squash or rebase) origin's $RELEASE_BRANCH into $RELEASE_BRANCH" >&2
            echo "       and cut the release from the merge: a new source, so a new candidate." >&2
        fi
        exit 1
    fi
    echo "  ✓ origin's $RELEASE_BRANCH (${origin_branch_commit:0:12}) can fast-forward to this release"
fi

if [ "$RESUME_PUBLISH" = "1" ]; then
    # The candidate's clean CI ran before it was built, and the tag push's hook
    # ran clean CI again against the published commit. Resume changes no source
    # and pushes nothing, so it goes straight to the verified post-push steps.
    echo "Steps 0-1: skipped under --resume-publish (no source change, build or push)"
else
    # Step 0a is deliberately deferred until after exact-candidate qualification.
    # A build-only first phase must not read publisher credentials or call a GitHub
    # publishing API; only the read-only origin queries above are allowed.
    # v1.10.0-rc audit fix:
    # Step 6 publishes both the Sparkle feed and the site's release metadata.
    # A missing token discovered after the tag/asset is public strands users on
    # stale distribution surfaces, so release.sh always requires it up front.
    # `SKIP_APPCAST=1` is deliberately narrow: it skips Sparkle only; it is not an
    # internal/dry-run escape hatch and cannot bypass release.json or the tap cask.
    # Step 0b: Pre-release check — enforce RELEASE_CHECKLIST.md items so the
    # pipeline refuses to ship out-of-sync versions, stale notes, or broken
    # localizations. Warnings still proceed; hard errors abort.
    echo "Step 0/6: Pre-release check..."
    if [ "$SKIP_PRERELEASE" = "1" ]; then
        echo "  (skipped via --skip-prerelease-check)"
    else
        "$SCRIPT_DIR/prerelease-check.sh" "$VERSION" || {
            echo "Pre-release check failed — fix the errors above or run with --skip-prerelease-check to override (not recommended)"
            exit 1
        }
    fi

    # Step 0b: Architectural-invariants audit (v1.6.19). Catches the
    # wire-the-orphans bug class and AlertSink-bypass regressions BEFORE
    # they ship. Sister script to prerelease-check.sh: that one verifies
    # manifest sync, this one verifies code structure.
    echo "Step 0b/6: Architectural audit..."
    "$SCRIPT_DIR/pre-release-audit.sh" || {
        echo "Architectural audit failed — fix the structural issues above before shipping"
        exit 1
    }

    # Step 1: clean local CI before the artifact build. Running the clean gate only
    # from the later tag push cannot retroactively prove that the signed DMG came
    # from freshly resolved release outputs. Credentials remain unexported here.
    echo "Step 1/6: Running clean local CI before the release build..."
    require_clean_release_source
    # Retain the complete aggregate transcript on success and failure. Candidate
    # manifests store only its digest/tail; private build cleanup must not remove it.
    if [ -L "$QUALIFICATION_DIR" ] \
            || { [ -e "$QUALIFICATION_DIR" ] && [ ! -d "$QUALIFICATION_DIR" ]; }; then
        echo "ERROR: refusing redirected/non-directory qualification evidence: $QUALIFICATION_DIR" >&2
        exit 1
    fi
    (umask 077; /bin/mkdir -p "$QUALIFICATION_DIR")
    CI_TRANSCRIPT=$(/usr/bin/mktemp "$QUALIFICATION_DIR/MacCrab-v$VERSION.clean-ci.XXXXXX")
    /bin/chmod 600 "$CI_TRANSCRIPT"
    echo "Aggregate clean-CI transcript retained at: $CI_TRANSCRIPT"
    CI_STARTED_AT=$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')
    if ! ./scripts/ci-local.sh --clean 2>&1 | /usr/bin/tee "$CI_TRANSCRIPT"; then
        echo "ERROR: clean local CI failed; no candidate will be recorded" >&2
        exit 1
    fi
    CI_COMPLETED_AT=$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')
    require_clean_release_source
    if [ "$($GIT_BIN rev-parse HEAD)" != "$SOURCE_COMMIT" ] \
            || [ "$($GIT_BIN rev-parse "$SOURCE_COMMIT^{tree}")" != "$SOURCE_TREE" ]; then
        echo "ERROR: clean CI changed the captured release source commit/tree" >&2
        exit 1
    fi
    verify_release_executor_blobs "$SOURCE_COMMIT"
fi

# Clean CI intentionally builds in the live worktree, while the release below
# builds again from an exact tracked-object export. Keeping both architecture
# trees resident at once adds several GiB of disposable peak usage and can make
# the second architecture fail after every source/test gate has passed. Remove
# only SwiftPM's explicitly named architecture products; release DMGs live at
# .build's top level and must remain byte-for-byte untouched.
reclaim_clean_ci_architecture_products() {
    local build_root="$PROJECT_DIR/.build"
    local architecture target
    reclaimed_architecture_products=0
    if [ -L "$build_root" ] || { [ -e "$build_root" ] && [ ! -d "$build_root" ]; }; then
        echo "ERROR: refusing to reclaim clean-CI products through invalid .build: $build_root" >&2
        return 1
    fi
    for architecture in arm64-apple-macosx x86_64-apple-macosx; do
        target="$build_root/$architecture"
        if [ -e "$target" ] || [ -L "$target" ]; then
            if [ -L "$target" ] || [ ! -d "$target" ]; then
                echo "ERROR: refusing to reclaim redirected/non-directory CI product: $target" >&2
                return 1
            fi
            /bin/rm -rf "$target"
            reclaimed_architecture_products=$((reclaimed_architecture_products + 1))
        fi
    done
}

if [ "$CANDIDATE_READY" != "1" ]; then
    reclaim_clean_ci_architecture_products
    # Every new build needs headroom on the private export's filesystem, even
    # when CI produced no architecture directory that required reclamation.
    release_free_kib=$(/bin/df -Pk /private/tmp | /usr/bin/awk 'NR == 2 { print $4 }')
    case "$release_free_kib" in
        ''|*[!0-9]*)
            echo "ERROR: could not measure free space for the exact release build" >&2
            exit 1
            ;;
    esac
    minimum_release_free_kib=$((3 * 1024 * 1024))
    if [ "$release_free_kib" -lt "$minimum_release_free_kib" ]; then
        echo "ERROR: exact dual-architecture release build requires at least 3 GiB free after CI-product reclamation; found $release_free_kib KiB" >&2
        exit 1
    fi
    echo "Clean CI products reclaimed ($reclaimed_architecture_products architecture tree(s)); exact release build headroom: $release_free_kib KiB"
fi

# All build stages run from an exact Git-object export, never from the live
# worktree. Ignored .swiftpm configuration, nested ignored resources, local
# package caches, and hidden-index modifications therefore cannot influence the
# artifact. The private export and immutable upload snapshot live until the
# complete downstream publication finishes.
BUILD_WORKSPACE=""
METADATA_INDEX=""
UPLOAD_SNAPSHOT_DIR=""
RESUME_METADATA_DIR=""
cleanup_release_private_state() {
    local status=$?
    trap - EXIT
    [ -z "$METADATA_INDEX" ] || /bin/rm -f "$METADATA_INDEX"
    [ -z "$BUILD_WORKSPACE" ] || /bin/rm -rf "$BUILD_WORKSPACE"
    [ -z "$UPLOAD_SNAPSHOT_DIR" ] || /bin/rm -rf "$UPLOAD_SNAPSHOT_DIR"
    [ -z "$RESUME_METADATA_DIR" ] || /bin/rm -rf "$RESUME_METADATA_DIR"
    exit "$status"
}
trap cleanup_release_private_state EXIT
BUILD_WORKSPACE=$(/usr/bin/mktemp -d /private/tmp/maccrab-release-build.XXXXXX)
/bin/chmod 700 "$BUILD_WORKSPACE"
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$HOME" TMPDIR=/private/tmp LC_ALL=C LANG=C \
    GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/python3 -I "$SCRIPT_DIR/export-release-source.py" \
    --repo "$PROJECT_DIR" --commit "$SOURCE_COMMIT" --destination "$BUILD_WORKSPACE"
if [ -e "$BUILD_WORKSPACE/.git" ] || [ -e "$BUILD_WORKSPACE/.swiftpm" ]; then
    echo "ERROR: tracked-only export contains forbidden Git/SwiftPM local state" >&2
    exit 1
fi
echo "Step 2/6: Exact tracked-only source exported from $SOURCE_COMMIT / $SOURCE_TREE"

# Step 3: either build a new exact candidate and stop, or reuse the already
# qualified candidate byte-for-byte. Publication never rebuilds after the host
# run: signing/notarization and DMG creation contain timestamps, so a rebuild
# would be a different, untested artifact even when the source tree is equal.
# v1.18 (sysext-zombie fix): give SHIPPED builds a DETERMINISTIC, monotonic
# CFBundleVersion (numeric base version + commit count) instead of build-release.sh's
# per-second epoch. Re-running a release on the same commit then reuses the
# same (version, build) tuple, so sysextd does not orphan a fresh
# "terminated waiting to uninstall on reboot" zombie for an identical
# rebuild (the audit found ~50 such never-reaped entries). The per-second
# epoch stays as build-release.sh's fallback for the dev loop (`make dev`
# rebuilds the SAME VERSION with changed code and needs a distinct tuple
# each time to force sysextd to replace the active extension).
# Marketing RC suffixes never enter CFBundleVersion: Sparkle ignores everything
# after a dash. RC and GA builds share the same numeric source-commit sequence.
echo "  Deterministic CFBundleVersion: $BUILD_NUMBER"

BUILD_DMG_PATH="$BUILD_WORKSPACE/.build/MacCrab-v$VERSION.dmg"
if [ "$CANDIDATE_READY" = "1" ]; then
    echo "Step 3/5: Reusing exact installed-host-qualified candidate..."
    assert_qualification_evidence_unchanged
    /bin/mkdir -p "$BUILD_WORKSPACE/.build"
    /bin/cp -p "$PROJECT_DIR/$DMG_PATH" "$BUILD_DMG_PATH"
    if ! is_nonempty_regular_release_artifact "$BUILD_DMG_PATH" \
            || [ "$($SHASUM_BIN -a 256 "$BUILD_DMG_PATH" | $AWK_BIN '{print $1}')" != "$QUALIFIED_CANDIDATE_SHA" ]; then
        echo "ERROR: exact candidate changed while entering the private publication workspace" >&2
        exit 1
    fi
    echo "  ✓ Preserved candidate copied unchanged (${QUALIFIED_CANDIDATE_SHA:0:16}...)"
    if [ "$VERSION_IS_RC" != "1" ]; then
        if [ "${SKIP_APPCAST:-0}" != "1" ]; then
            # This fresh export never built SwiftPM dependencies. Carry only
            # the pinned appcast tools from the just-validated CI checkout;
            # authenticate both ends before publisher credentials or tags.
            /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
                /bin/bash "$SCRIPT_DIR/check-release-dependencies.sh"
            /bin/mkdir -p "$BUILD_WORKSPACE/.build/checkouts/Sparkle" \
                "$BUILD_WORKSPACE/.build/artifacts/sparkle/Sparkle/bin"
            for sparkle_input in \
                .build/checkouts/Sparkle/Package.swift \
                .build/artifacts/sparkle/Sparkle/bin/sign_update \
                .build/artifacts/sparkle/Sparkle/bin/generate_keys; do
                /bin/cp -p "$PROJECT_DIR/$sparkle_input" "$BUILD_WORKSPACE/$sparkle_input"
            done
            /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
                /bin/bash "$BUILD_WORKSPACE/scripts/check-release-dependencies.sh"
            echo "  ✓ Pinned Sparkle appcast tools verified in the publication export"
        fi
        # A resumed release publishes the release.json its tag already names;
        # regenerating it would stamp a new release_date the tag does not carry.
        if [ "$RESUME_PUBLISH" != "1" ]; then
            /usr/bin/python3 -I "$SCRIPT_DIR/candidate-qualification.py" emit-release-json \
                --version "$VERSION" \
                --source-root "$BUILD_WORKSPACE" \
                --candidate-manifest "$CANDIDATE_MANIFEST" \
                --output "$BUILD_WORKSPACE/release.json"
        fi
    fi
else
    echo "Step 3/5: Building an exact candidate (publication will stop after the build)..."
    if [ "$VERSION_IS_RC" = "1" ]; then
        RELEASE_BUILD_CHANNEL=dev
    else
        RELEASE_BUILD_CHANNEL=release
    fi
    (
        cd "$BUILD_WORKSPACE"
        MACCRAB_REQUIRE_TRACKED_RELEASE_INPUTS=1 MACCRAB_TRACKED_EXPORT=1 \
            MACCRAB_RELEASE_SOURCE_COMMIT="$SOURCE_COMMIT" MACCRAB_RELEASE_SOURCE_TREE="$SOURCE_TREE" \
            VERSION="$VERSION" BUILD_NUMBER="$BUILD_NUMBER" MACCRAB_BUILD_CHANNEL="$RELEASE_BUILD_CHANNEL" \
            ./scripts/build-release.sh unsigned-build
        MACCRAB_TRACKED_EXPORT=1 MACCRAB_RELEASE_SOURCE_COMMIT="$SOURCE_COMMIT" \
            MACCRAB_RELEASE_SOURCE_TREE="$SOURCE_TREE" VERSION="$VERSION" BUILD_NUMBER="$BUILD_NUMBER" \
            MACCRAB_BUILD_CHANNEL="$RELEASE_BUILD_CHANNEL" ./scripts/build-release.sh assemble
        DEVELOPER_ID="$MACCRAB_SIGN_DEVELOPER_ID" MACCRAB_TRACKED_EXPORT=1 \
            MACCRAB_RELEASE_SOURCE_COMMIT="$SOURCE_COMMIT" MACCRAB_RELEASE_SOURCE_TREE="$SOURCE_TREE" \
            VERSION="$VERSION" BUILD_NUMBER="$BUILD_NUMBER" MACCRAB_BUILD_CHANNEL="$RELEASE_BUILD_CHANNEL" \
            ./scripts/build-release.sh sign
        DEVELOPER_ID="$MACCRAB_SIGN_DEVELOPER_ID" \
        APPLE_ID="$MACCRAB_SIGN_APPLE_ID" \
        APPLE_TEAM_ID="$MACCRAB_SIGN_APPLE_TEAM_ID" \
        NOTARIZE_PASSWORD="$MACCRAB_SIGN_NOTARIZE_PASSWORD" \
        NOTARIZE_KEYCHAIN_PROFILE="$MACCRAB_SIGN_NOTARIZE_KEYCHAIN_PROFILE" \
        MACCRAB_TRACKED_EXPORT=1 MACCRAB_RELEASE_SOURCE_COMMIT="$SOURCE_COMMIT" \
        MACCRAB_RELEASE_SOURCE_TREE="$SOURCE_TREE" VERSION="$VERSION" BUILD_NUMBER="$BUILD_NUMBER" \
            MACCRAB_BUILD_CHANNEL="$RELEASE_BUILD_CHANNEL" ./scripts/build-release.sh publish
    )
    if ! is_nonempty_regular_release_artifact "$BUILD_DMG_PATH"; then
        echo "ERROR: tracked-only build did not produce a non-empty regular release DMG at $BUILD_DMG_PATH" >&2
        exit 1
    fi
    /bin/mkdir -p "$PROJECT_DIR/.build" "$QUALIFICATION_DIR"
    /bin/cp -p "$BUILD_DMG_PATH" "$PROJECT_DIR/$DMG_PATH"
    if ! is_nonempty_regular_release_artifact "$DMG_PATH"; then
        echo "ERROR: build did not produce a non-empty regular release DMG at $DMG_PATH" >&2
        exit 1
    fi
    NOTARY_ID_FILE="$BUILD_DMG_PATH.notary-submission-id"
    if ! is_regular_evidence_file "$NOTARY_ID_FILE"; then
        echo "ERROR: candidate lacks its accepted notarization submission identity: $NOTARY_ID_FILE" >&2
        echo "An unnotarized candidate cannot represent the shipped form." >&2
        exit 1
    fi
    NOTARY_SUBMISSION_ID=$($SED_BIN -n 's/^notary_submission_id=//p' "$NOTARY_ID_FILE" | /usr/bin/head -1)
    /usr/bin/python3 -I "$SCRIPT_DIR/candidate-qualification.py" record-candidate \
        --version "$VERSION" \
        --build-number "$BUILD_NUMBER" \
        --source-commit "$SOURCE_COMMIT" \
        --source-tree "$SOURCE_TREE" \
        --source-root "$PROJECT_DIR" \
        --dmg "$PROJECT_DIR/$DMG_PATH" \
        --notarization-submission-id "$NOTARY_SUBMISSION_ID" \
        --clean-ci-transcript "$CI_TRANSCRIPT" \
        --clean-ci-started-at "$CI_STARTED_AT" \
        --clean-ci-completed-at "$CI_COMPLETED_AT" \
        --output "$CANDIDATE_MANIFEST"
    if ! is_regular_evidence_file "$RUNTIME_REPORT"; then
        /usr/bin/python3 -I "$SCRIPT_DIR/candidate-qualification.py" runtime-template \
            --candidate-manifest "$CANDIDATE_MANIFEST" \
            --output "$RUNTIME_REPORT"
    fi
    print_qualification_next_steps
    exit 3 # exact-candidate-phase-boundary: fixture tests patch only their disposable copy
fi

# This is the irreversible phase boundary. Everything above may build or inspect
# local bytes; nothing below is reachable until the second full verification of
# the preserved candidate and both host reports. No --skip-prerelease-check,
# --respin, RC flag, or environment override bypasses this call.
assert_qualification_evidence_unchanged
run_candidate_qualification_gate
assert_qualification_evidence_unchanged

# Only now read publisher credentials and contact GitHub/distribution services.
# A first-phase build exits above without exposing these credentials or making
# any artifact public; its earlier Apple notarization submission is the required
# non-public exception.
load_publisher_values
if [ ! -x "$GH_BIN" ]; then
    echo "ERROR: GitHub CLI (gh) is required to publish the release asset." >&2
    echo "Install/authenticate gh after candidate qualification, before publication." >&2
    exit 1
fi
require_canonical_origin
if ! publisher_gh api user >/dev/null 2>&1; then
    echo "ERROR: GitHub CLI authentication is invalid or expired." >&2
    echo "Run 'gh auth login' and verify access before tagging or publishing." >&2
    exit 1
fi
gh_repo_can_push=$(publisher_gh api "repos/$CANONICAL_GH_REPO" --jq '.permissions.push // false' 2>/dev/null || true)
if [ "$gh_repo_can_push" != "true" ]; then
    echo "ERROR: GitHub CLI credentials cannot publish to this repository." >&2
    exit 1
fi
if [ "$VERSION_IS_RC" != "1" ] && [ -z "$MACCRAB_PUBLISH_SITE_REPO_TOKEN" ]; then
    echo "ERROR: SITE_REPO_TOKEN env var not set." >&2
    echo "release.json, the Sparkle feed, and the Homebrew cask remain mandatory." >&2
    exit 1
fi

# (v1.6.11) PKG build removed — productbuild's distribution-XML
# pkg-ref name didn't match the component pkg filename, producing
# a 1.9KB stub archive that opened in Installer.app but contained
# no payload. DMG + Homebrew are the supported install paths.

# Step 4: Update Homebrew formulae
#
# The repo historically has TWO cask files — homebrew/maccrab.rb (legacy,
# in-tree docs) and Casks/maccrab.rb (what the Homebrew tap actually
# reads when this repo is tapped via `brew tap peterhanily/maccrab`).
# Pre-v1.6.14 the script only updated homebrew/maccrab.rb, so every
# release since v1.6.5 landed with a stale Casks/maccrab.rb — brew
# users saw old versions for nine releases before anyone noticed.
# Both files are now updated in lockstep.
SHA=$($SHASUM_BIN -a 256 "$DMG_PATH" | $AWK_BIN '{print $1}')
# Where the steps below read release.json, the casks and the release notes. A
# normal run copies its generated metadata into the worktree and commits
# exactly those bytes, so the worktree holds the tagged commit's files. A
# resumed release reads them from the published tag's commit instead: the
# checkout may be a later merge, and the release must describe what the
# public tag names.
RELEASE_METADATA_ROOT="$PROJECT_DIR"
if [ "$RESUME_PUBLISH" = "1" ]; then
    echo "Step 4/5: Resuming published v$VERSION; metadata comes from its commit ${release_tag_commit:0:12}"
    FINAL_COMMIT=$release_tag_commit
    TAG_OBJECT=$release_tag_object
    RESUME_METADATA_DIR=$(/usr/bin/mktemp -d /private/tmp/maccrab-release-metadata.XXXXXX)
    /bin/chmod 700 "$RESUME_METADATA_DIR"
    /bin/mkdir -p "$RESUME_METADATA_DIR/Casks" "$RESUME_METADATA_DIR/homebrew" \
        "$RESUME_METADATA_DIR/RELEASE_NOTES"
    for metadata_path in release.json Casks/maccrab.rb homebrew/maccrab.rb "RELEASE_NOTES/v$VERSION.md"; do
        if $GIT_BIN cat-file -e "$FINAL_COMMIT:$metadata_path" 2>/dev/null; then
            $GIT_BIN cat-file blob "$FINAL_COMMIT:$metadata_path" > "$RESUME_METADATA_DIR/$metadata_path"
        fi
    done
    RELEASE_METADATA_ROOT=$RESUME_METADATA_DIR
else
    if [ "$VERSION_IS_RC" != "1" ] && is_nonempty_regular_release_artifact "$DMG_PATH"; then
        echo "Step 4/5: Updating Homebrew formulae..."
        for formula in homebrew/maccrab.rb Casks/maccrab.rb; do
            if [ -f "$BUILD_WORKSPACE/$formula" ]; then
                $SED_BIN -i '' "s/version \".*\"/version \"$VERSION\"/" "$BUILD_WORKSPACE/$formula"
                $SED_BIN -i '' "s/sha256 .*/sha256 \"$SHA\"/" "$BUILD_WORKSPACE/$formula"
                echo "  Generated $formula (sha256: ${SHA:0:16}...)"
            fi
        done
    else
        echo "Step 4/5: RC isolation — production Homebrew casks remain unchanged."
    fi

    # Re-assert the captured source before copying generated metadata back. Only
    # these three files may differ, and they are committed below through a private
    # temporary index rather than an extensible commit hook.
    require_clean_release_source
    if [ "$($GIT_BIN rev-parse HEAD)" != "$SOURCE_COMMIT" ]; then
        echo "ERROR: HEAD changed while the tracked-only artifact was built" >&2
        exit 1
    fi
    verify_release_executor_blobs "$SOURCE_COMMIT"
    if [ "$VERSION_IS_RC" != "1" ]; then
        for metadata_path in release.json Casks/maccrab.rb homebrew/maccrab.rb; do
            if [ ! -f "$BUILD_WORKSPACE/$metadata_path" ] || [ -L "$BUILD_WORKSPACE/$metadata_path" ]; then
                echo "ERROR: tracked-only build did not produce required GA metadata: $metadata_path" >&2
                exit 1
            fi
            /bin/cp -p "$BUILD_WORKSPACE/$metadata_path" "$PROJECT_DIR/$metadata_path"
        done
    fi
fi

# Step 5: Create GitHub release
echo "Step 5/5: Creating GitHub release..."
# release.json is regenerated by build-release.sh (:1125) with the freshly built
# DMG's sha256 + size, but it was never staged — so every tag pointed at a commit
# whose release.json still carried the PREVIOUS build's hash. v1.21.5's tagged
# tree says 6611efa8 while the DMG that actually shipped is 9eb6f493. Stage it
# alongside the casks so the tagged tree describes the artifact being tagged.
# Step 5a: PRE-TAG artifact/manifest consistency gate.
#
# The cross-source SHA check (Step 6c) ran AFTER `git tag`, `git push` and
# `gh release create`, only when SITE_REPO_TOKEN was set, and never exited
# non-zero — it could observe divergence but structurally could not prevent it.
# Assert HERE, while nothing has been published and nothing is tagged, that
# release.json and both casks describe the DMG we are about to ship. Any
# mismatch aborts before a single byte reaches users.
if ! is_nonempty_regular_release_artifact "$DMG_PATH"; then
    echo "  ✗ Built release artifact is missing, empty, non-regular, or redirected: $DMG_PATH" >&2
    exit 1
fi
gate_dmg_sha=$($SHASUM_BIN -a 256 "$DMG_PATH" | $AWK_BIN '{print $1}')
if [ "$VERSION_IS_RC" != "1" ]; then
    gate_json_sha=$($GREP_BIN -oE '"sha256"[[:space:]]*:[[:space:]]*"[a-f0-9]{64}"' "$RELEASE_METADATA_ROOT/release.json" 2>/dev/null | /usr/bin/head -1 | $GREP_BIN -oE '[a-f0-9]{64}' || true)
    if [ "$gate_json_sha" != "$gate_dmg_sha" ]; then
        echo "  ✗ release.json sha256 ($gate_json_sha) != built DMG ($gate_dmg_sha)" >&2
        echo "    Re-run scripts/build-release.sh so release.json describes THIS DMG." >&2
        exit 1
    fi
    for gate_cask in Casks/maccrab.rb homebrew/maccrab.rb; do
        [ -f "$RELEASE_METADATA_ROOT/$gate_cask" ] || {
            echo "  ✗ required GA cask is missing: $gate_cask" >&2
            exit 1
        }
        gate_cask_sha=$($GREP_BIN -oE 'sha256[[:space:]]+"[a-f0-9]{64}"' "$RELEASE_METADATA_ROOT/$gate_cask" | /usr/bin/head -1 | $GREP_BIN -oE '[a-f0-9]{64}' || true)
        if [ "$gate_cask_sha" != "$gate_dmg_sha" ]; then
            echo "  ✗ $gate_cask sha256 ($gate_cask_sha) != built DMG ($gate_dmg_sha)" >&2
            echo "    brew install --cask would fail checksum verification for every user." >&2
            exit 1
        fi
    done
    echo "  ✓ Pre-tag gate: release.json + casks all describe DMG ${gate_dmg_sha:0:16}..."
else
    echo "  ✓ RC pre-tag gate: artifact hashed; production release.json and casks were not touched."
fi

validate_generated_release_paths() {
    local changed staged
    changed=$($GIT_BIN diff --name-only | LC_ALL=C /usr/bin/sort)
    staged=$($GIT_BIN diff --cached --name-only)
    if [ -n "$staged" ]; then
        echo "ERROR: release generation found a pre-staged path; metadata index must be isolated" >&2
        printf '%s\n' "$staged" >&2
        return 1
    fi
    if [ "$VERSION_IS_RC" = "1" ]; then
        if [ -n "$changed" ]; then
            echo "ERROR: RC build changed the captured production source tree" >&2
            printf '%s\n' "$changed" >&2
            return 1
        fi
    elif [ "$changed" != $'Casks/maccrab.rb\nhomebrew/maccrab.rb\nrelease.json' ]; then
        echo "ERROR: GA generation did not produce the exact metadata allowlist" >&2
        printf '%s\n' "$changed" >&2
        return 1
    fi
}
# A resumed release already has its tagged metadata commit: nothing is
# generated, committed or moved.
if [ "$RESUME_PUBLISH" != "1" ]; then
    validate_generated_release_paths

    if [ "$VERSION_IS_RC" = "1" ]; then
        METADATA_TREE="$SOURCE_TREE"
        FINAL_COMMIT="$SOURCE_COMMIT"
    else
        METADATA_INDEX=$(/usr/bin/mktemp /private/tmp/maccrab-release-index.XXXXXX)
        /bin/rm -f "$METADATA_INDEX"
        GIT_INDEX_FILE="$METADATA_INDEX" $GIT_BIN -c core.hooksPath=/dev/null \
            read-tree "$SOURCE_TREE"
        for metadata_path in release.json Casks/maccrab.rb homebrew/maccrab.rb; do
            metadata_source_entry=$($GIT_BIN ls-tree "$SOURCE_TREE" -- "$metadata_path")
            IFS=$' \t' read -r metadata_mode metadata_type metadata_source_blob \
                metadata_source_name <<< "$metadata_source_entry"
            if [ "$metadata_mode" != "100644" ] || [ "$metadata_type" != "blob" ] \
                    || [ "$metadata_source_name" != "$metadata_path" ]; then
                echo "ERROR: GA metadata source is not an ordinary tracked file: $metadata_path" >&2
                exit 1
            fi
            metadata_working_blob=$($GIT_BIN hash-object -w --no-filters "$metadata_path")
            GIT_INDEX_FILE="$METADATA_INDEX" $GIT_BIN -c core.hooksPath=/dev/null \
                update-index --add --cacheinfo \
                "$metadata_mode,$metadata_working_blob,$metadata_path"
        done
        METADATA_TREE=$(GIT_INDEX_FILE="$METADATA_INDEX" $GIT_BIN write-tree)
        metadata_diff=$($GIT_BIN diff-tree --no-commit-id --name-only -r \
            "$SOURCE_TREE" "$METADATA_TREE" | LC_ALL=C /usr/bin/sort)
        if [ "$metadata_diff" != $'Casks/maccrab.rb\nhomebrew/maccrab.rb\nrelease.json' ]; then
            echo "ERROR: precomputed metadata tree differs outside the exact allowlist" >&2
            printf '%s\n' "$metadata_diff" >&2
            exit 1
        fi
        for metadata_path in release.json Casks/maccrab.rb homebrew/maccrab.rb; do
            metadata_blob=$($GIT_BIN rev-parse "$METADATA_TREE:$metadata_path" 2>/dev/null || true)
            working_blob=$($GIT_BIN hash-object --no-filters "$metadata_path" 2>/dev/null || true)
            if [ -z "$metadata_blob" ] || [ "$working_blob" != "$metadata_blob" ]; then
                echo "ERROR: precomputed metadata blob changed before commit: $metadata_path" >&2
                exit 1
            fi
        done
        FINAL_COMMIT=$($GIT_BIN -c core.hooksPath=/dev/null \
            commit-tree "$METADATA_TREE" -p "$SOURCE_COMMIT" \
            -m "chore: update release metadata to v$VERSION")
        $GIT_BIN -c core.hooksPath=/dev/null update-ref \
            "refs/heads/$RELEASE_BRANCH" "$FINAL_COMMIT" "$SOURCE_COMMIT"
        $GIT_BIN -c core.hooksPath=/dev/null read-tree "$FINAL_COMMIT"
    fi

    # The final commit is either the exact source commit (RC) or one hookless,
    # single-parent metadata commit with the precomputed tree. No pre-commit or
    # commit-msg hook is part of this trust transition.
    if [ "$($GIT_BIN rev-parse HEAD)" != "$FINAL_COMMIT" ] \
            || [ "$($GIT_BIN rev-parse "$SOURCE_COMMIT^{tree}")" != "$SOURCE_TREE" ] \
            || [ "$($GIT_BIN rev-parse "$FINAL_COMMIT^{tree}")" != "$METADATA_TREE" ]; then
        echo "ERROR: final release commit/source/metadata tree binding failed" >&2
        exit 1
    fi
    if [ "$FINAL_COMMIT" != "$SOURCE_COMMIT" ] \
            && [ "$($GIT_BIN rev-list --parents -n 1 "$FINAL_COMMIT")" != "$FINAL_COMMIT $SOURCE_COMMIT" ]; then
        echo "ERROR: final metadata commit is not the captured source's single child" >&2
        exit 1
    fi
    reject_hidden_release_index_state
    final_dirty=$($GIT_BIN status --porcelain --untracked-files=all)
    if [ -n "$final_dirty" ]; then
        echo "  ✗ Files remain outside the final release commit:" >&2
        printf '%s\n' "$final_dirty" >&2
        exit 1
    fi
    verify_release_executor_blobs "$FINAL_COMMIT"
    EXPECTED_HOOK_BLOB=$($GIT_BIN rev-parse "$FINAL_COMMIT:.githooks/pre-push")
    CURRENT_HOOK_BLOB=$($GIT_BIN hash-object --no-filters "$VERSIONED_PRE_PUSH")
    if [ "$EXPECTED_HOOK_BLOB" != "$CURRENT_HOOK_BLOB" ]; then
        echo "ERROR: the executable pre-push hook bytes do not match the final release commit" >&2
        exit 1
    fi
fi

# Never let an upload failure path delete a release that predated this run.
# Establish an authoritative HTTP 404 before creating/moving the local tag; a
# generic CLI/network failure is not evidence of absence and must fail closed.
github_release_probe=""
github_release_probe_status=0
if github_release_probe=$(publisher_gh api -i \
        "repos/$CANONICAL_GH_REPO/releases/tags/v$VERSION" 2>&1); then
    echo "  ✗ GitHub release v$VERSION already exists." >&2
    echo "    Refusing to replace or roll back a release this run did not create." >&2
    exit 1
else
    github_release_probe_status=$?
fi
if ! printf '%s\n' "$github_release_probe" \
        | $GREP_BIN -qE 'HTTP(/[^[:space:]]+)?[[:space:]]+404|\(HTTP 404\)'; then
    echo "  ✗ Could not prove GitHub release v$VERSION is absent" \
        "(probe exit $github_release_probe_status)." >&2
    echo "    Refusing to begin a draft publication with indeterminate remote state." >&2
    exit 1
fi

if [ "$RESUME_PUBLISH" != "1" ]; then
    # Existing-tag handling. Pre-fix `git tag` simply failed here under `set -e`,
    # aborting the release after the build + notarize had already completed.
    if $GIT_BIN rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then
        if [ "$RESPIN" = "1" ]; then
            echo "  Re-spin: moving tag v$VERSION from $($GIT_BIN rev-parse --short "v$VERSION") to $($GIT_BIN rev-parse --short HEAD)"
            $GIT_BIN tag -d "v$VERSION"
        else
            echo "  ✗ Tag v$VERSION already exists (at $($GIT_BIN rev-parse --short "v$VERSION"))." >&2
            echo "    Bump the version, or pass --respin to re-point it at this build." >&2
            exit 1
        fi
    fi

    # Annotated — and signed when a signing key is configured — tags. Every release
    # tag through v1.21.5 is a LIGHTWEIGHT ref: `git tag -v` reports "cannot verify a
    # non-tag object of type commit", so no release carries a tagger identity, a
    # message, or any cryptographic binding to the maintainer, and anyone with repo
    # write can silently move one. Annotated is the floor; signing is applied when
    # available rather than made mandatory, because an unconditional `git tag -s` on
    # a machine with no user.signingkey would hard-fail every release.
    if [ -n "$($GIT_BIN config --get user.signingkey || true)" ]; then
        $GIT_BIN tag -s "v$VERSION" -m "MacCrab v$VERSION"
        echo "  ✓ Signed annotated tag v$VERSION"
    else
        echo "  ! No git user.signingkey configured — creating an ANNOTATED (unsigned) tag." >&2
        echo "    Enable signing so releases are verifiable by users and mirrors:" >&2
        echo "      git config gpg.format ssh && git config user.signingkey ~/.ssh/id_ed25519.pub" >&2
        $GIT_BIN tag -a "v$VERSION" -m "MacCrab v$VERSION"
    fi
    TAG_OBJECT=$($GIT_BIN rev-parse "refs/tags/v$VERSION")
    TAG_TYPE=$($GIT_BIN cat-file -t "$TAG_OBJECT")
    TAG_COMMIT=$($GIT_BIN rev-parse "$TAG_OBJECT^{commit}")
    if [ "$TAG_TYPE" != "tag" ] || [ "$TAG_COMMIT" != "$FINAL_COMMIT" ]; then
        echo "ERROR: release tag is not an annotated tag bound to final commit $FINAL_COMMIT" >&2
        exit 1
    fi

    # ORDER MATTERS — the tag goes to the remote BEFORE the release branch.
    #
    # Only the tag push's pre-push hook runs `ci-local.sh --clean`: the from-scratch
    # build, the full suite, and the release manifest expectations. A branch push
    # gets the warm run. Pushing the branch first therefore published the release
    # metadata commit to a PUBLIC main before the authoritative gate had any chance
    # to fail — and when it did fail, main advertised a `release.json` whose
    # `dmg.url` 404s plus an in-tree cask naming a sha256 for a DMG nobody could
    # download, with no release object to back either.
    #
    # Tag first inverts the failure mode. If the clean gate fails, nothing is public
    # at all. If the gate passes but the later branch push fails, the remote holds a
    # fully verified annotated tag and a main that is one commit behind: recoverable
    # and never misleading, which the old order could not say.
    #
    # Both pushes run arbitrary project checks that could themselves alter local Git
    # configuration, so the full release state is re-asserted immediately before each
    # one. One implementation, called twice — the two copies used to drift.
    assert_release_state_unchanged() {
        local stage="$1"
        require_canonical_origin
        require_versioned_pre_push_gate
        assert_qualification_evidence_unchanged "$stage"
        reject_hidden_release_index_state
        verify_release_executor_blobs "$FINAL_COMMIT"
        if [ "$($GIT_BIN rev-parse HEAD)" != "$FINAL_COMMIT" ] \
                || [ "$($GIT_BIN rev-parse "$SOURCE_COMMIT^{tree}")" != "$SOURCE_TREE" ] \
                || [ "$($GIT_BIN rev-parse "$FINAL_COMMIT^{tree}")" != "$METADATA_TREE" ] \
                || [ -n "$($GIT_BIN status --porcelain --untracked-files=all)" ] \
                || [ "$($GIT_BIN hash-object --no-filters "$VERSIONED_PRE_PUSH")" != "$EXPECTED_HOOK_BLOB" ] \
                || [ "$($GIT_BIN rev-parse "refs/tags/v$VERSION")" != "$TAG_OBJECT" ] \
                || [ "$($GIT_BIN rev-parse "$TAG_OBJECT^{commit}")" != "$FINAL_COMMIT" ]; then
            echo "ERROR: HEAD, source, hook, or release tag drifted; refusing $stage" >&2
            exit 1
        fi
    }

    # Nothing is public when the tag push is refused, but this run has already
    # created the local tag and, for a GA, moved the local branch to its metadata
    # commit. Say so, and how to return to the source checkout.
    print_unpushed_release_restore() {
        echo "       Nothing was pushed. This run created local tag v$VERSION; to restore:" >&2
        echo "         git tag -d v$VERSION" >&2
        if [ "$FINAL_COMMIT" != "$SOURCE_COMMIT" ]; then
            echo "         git update-ref refs/heads/$RELEASE_BRANCH $SOURCE_COMMIT $FINAL_COMMIT" >&2
            echo "         git restore --source=HEAD --staged --worktree -- release.json Casks/maccrab.rb homebrew/maccrab.rb" >&2
        fi
    }

    # The preflight read origin before clean CI and the build, possibly an hour
    # ago. Re-read it now, while nothing is public: a v$VERSION that no longer
    # matches the lease would otherwise be refused only once the push is under
    # way, and a branch that moved in the meantime would fail the branch push and
    # strand the public tag, as v1.22.2's was.
    require_origin_unchanged_for_tag_push() {
        local remote_tag
        remote_tag=$($GIT_BIN ls-remote origin "refs/tags/v$VERSION" \
            | $AWK_BIN -v ref="refs/tags/v$VERSION" '$2 == ref && !found { print $1; found = 1 }')
        if [ "$remote_tag" != "$tag_push_lease_object" ]; then
            echo "ERROR: origin's v$VERSION changed after the preflight; refusing the tag push." >&2
            echo "  expected: ${tag_push_lease_object:-<absent>}" >&2
            echo "  remote:   ${remote_tag:-<absent>}" >&2
            print_unpushed_release_restore
            exit 1
        fi
        if ! origin_release_branch_fast_forwards; then
            echo "ERROR: origin's $RELEASE_BRANCH moved during the release to ${origin_branch_commit:-<missing>}," >&2
            echo "       which is not an ancestor of source $SOURCE_COMMIT, so the branch push after" >&2
            echo "       the tag push could not fast-forward. Refusing the tag push." >&2
            echo "       Merge (never squash or rebase) origin's $RELEASE_BRANCH into $RELEASE_BRANCH" >&2
            echo "       and cut the release from the merge: a new source, so a new candidate." >&2
            print_unpushed_release_restore
            exit 1
        fi
    }

    assert_release_state_unchanged "tag push"
    require_origin_unchanged_for_tag_push
    if [ "$RESPIN" = "1" ]; then
        # The lease names the tag object proven replaceable in the preflight, or is
        # empty ("must not exist") when origin had no v$VERSION. It covers the window
        # between that ls-remote and this push's own ref advertisement, which spans
        # clean CI and the build; the re-read just above makes a stale lease fail
        # before the hook runs its clean CI. A tag moved while the push itself runs,
        # hook included, is refused by receive-pack's compare-and-swap against the
        # advertised value.
        MACCRAB_RELEASE_EXPECTED_DMG="$DMG_PATH" \
        MACCRAB_RELEASE_EXPECTED_SHA256="$gate_dmg_sha" \
        MACCRAB_RELEASE_EXPECTED_COMMIT="$FINAL_COMMIT" \
        MACCRAB_RELEASE_EXPECTED_TAG_OBJECT="$TAG_OBJECT" \
        MACCRAB_RELEASE_EXPECTED_HOOK_BLOB="$EXPECTED_HOOK_BLOB" \
        MACCRAB_RELEASE_SOURCE_COMMIT="$SOURCE_COMMIT" \
        MACCRAB_RELEASE_SOURCE_TREE="$SOURCE_TREE" \
        MACCRAB_RELEASE_METADATA_TREE="$METADATA_TREE" \
            $GIT_BIN push --force-with-lease="refs/tags/v$VERSION:$tag_push_lease_object" \
                origin "refs/tags/v$VERSION"
    else
        MACCRAB_RELEASE_EXPECTED_DMG="$DMG_PATH" \
        MACCRAB_RELEASE_EXPECTED_SHA256="$gate_dmg_sha" \
        MACCRAB_RELEASE_EXPECTED_COMMIT="$FINAL_COMMIT" \
        MACCRAB_RELEASE_EXPECTED_TAG_OBJECT="$TAG_OBJECT" \
        MACCRAB_RELEASE_EXPECTED_HOOK_BLOB="$EXPECTED_HOOK_BLOB" \
        MACCRAB_RELEASE_SOURCE_COMMIT="$SOURCE_COMMIT" \
        MACCRAB_RELEASE_SOURCE_TREE="$SOURCE_TREE" \
        MACCRAB_RELEASE_METADATA_TREE="$METADATA_TREE" \
            $GIT_BIN push origin "refs/tags/v$VERSION"
    fi

    require_canonical_origin
    remote_tag_object=$($GIT_BIN ls-remote origin "refs/tags/v$VERSION" | $AWK_BIN 'NR == 1 {print $1}')
    if [ "$remote_tag_object" != "$TAG_OBJECT" ]; then
        echo "ERROR: remote tag object does not match the locally verified annotated tag" >&2
        echo "  expected: $TAG_OBJECT" >&2
        echo "  remote:   ${remote_tag_object:-<missing>}" >&2
        exit 1
    fi

    # The clean gate has now passed and the verified tag is on the remote. Only now
    # does the release branch move. Push THIS commit explicitly: `git push origin
    # main --tags` pushed the local `main` ref — which need not contain HEAD — plus
    # every stray local tag in the repo.
    #
    # v1.22.2's branch push failed here (the hook's CI ran out of disk) and set -e
    # ended the run without saying that the tag was already public or how to
    # finish. Say both.
    print_branch_push_recovery() {
        echo "" >&2
        echo "PUBLICATION STOPPED: the $RELEASE_BRANCH push failed after the release tag was pushed." >&2
        echo "  v$VERSION is public and verified: annotated tag $TAG_OBJECT on $FINAL_COMMIT." >&2
        echo "  origin's $RELEASE_BRANCH did not move, and no GitHub release, appcast, release.json" >&2
        echo "  or cask was published. Do not move or delete the tag, and do not rebuild." >&2
        echo "" >&2
        echo "  Fix the push failure above, make origin's $RELEASE_BRANCH contain $FINAL_COMMIT" >&2
        echo "  by a merge (never squash or rebase), then publish from the existing tag. Run the" >&2
        echo "  resume from the tagged commit in this directory, not from the merge: the" >&2
        echo "  qualification gate re-reads this checkout, and the merge can bring in later rule" >&2
        echo "  or workload changes that fail it." >&2
        echo "    git fetch origin" >&2
        echo "    git merge origin/$RELEASE_BRANCH" >&2
        echo "    git push origin $RELEASE_BRANCH" >&2
        echo "    git checkout --detach $FINAL_COMMIT" >&2
        echo "    $RESUME_COMMAND" >&2
        if [ "$FINAL_COMMIT" != "$SOURCE_COMMIT" ]; then
            echo "" >&2
            echo "  This run already moved local refs/heads/$RELEASE_BRANCH from $SOURCE_COMMIT" >&2
            echo "  to $FINAL_COMMIT (git update-ref); the steps above build on that. To return" >&2
            echo "  it to the source instead, for example to rerun from the source:" >&2
            echo "    git update-ref refs/heads/$RELEASE_BRANCH $SOURCE_COMMIT $FINAL_COMMIT" >&2
            echo "    git restore --source=HEAD --staged --worktree -- release.json Casks/maccrab.rb homebrew/maccrab.rb" >&2
        fi
    }
    assert_release_state_unchanged "branch push"
    if ! $GIT_BIN push origin "HEAD:refs/heads/$RELEASE_BRANCH"; then
        print_branch_push_recovery
        exit 1
    fi
    require_canonical_origin
    remote_branch_commit=$($GIT_BIN ls-remote origin "refs/heads/$RELEASE_BRANCH" | $AWK_BIN 'NR == 1 {print $1}')
    if [ "$remote_branch_commit" != "$FINAL_COMMIT" ]; then
        echo "ERROR: remote $RELEASE_BRANCH does not point at the verified release commit" >&2
        echo "  expected: $FINAL_COMMIT" >&2
        echo "  remote:   ${remote_branch_commit:-<missing>}" >&2
        exit 1
    fi
else
    # The gate and publisher checks above can take minutes. Re-read origin
    # before creating anything: v$VERSION must still be the tag verified in
    # the preflight, and the release branch must still contain its commit.
    remote_tag_object=$($GIT_BIN ls-remote origin "refs/tags/v$VERSION" \
        | $AWK_BIN -v ref="refs/tags/v$VERSION" '$2 == ref && !found { print $1; found = 1 }')
    if [ "$remote_tag_object" != "$TAG_OBJECT" ] \
            || ! origin_release_branch_contains "$FINAL_COMMIT"; then
        echo "ERROR: origin changed during the resume: v$VERSION is ${remote_tag_object:-<absent>}" >&2
        echo "       (expected $TAG_OBJECT) and $RELEASE_BRANCH is ${origin_branch_commit:-<missing>}," >&2
        echo "       which must contain $FINAL_COMMIT. Nothing was published." >&2
        exit 1
    fi
    echo "  ✓ Resume: origin still has v$VERSION (${TAG_OBJECT:0:12}); $RELEASE_BRANCH contains ${FINAL_COMMIT:0:12}"
fi

# The tag push runs the pre-push hook's clean CI gate. That gate historically
# wiped .build and therefore deleted the signed + notarized + stapled DMG before
# this upload step. Never turn a missing (or replaced) artifact into a successful
# release: re-check the exact bytes that passed the pre-tag manifest gate.
if ! is_nonempty_regular_release_artifact "$DMG_PATH"; then
    echo "  ✗ Release artifact disappeared, became empty/non-regular, or was redirected during the push/CI gate: $DMG_PATH" >&2
    echo "    The tag exists remotely, but no GitHub release asset was uploaded." >&2
    echo "    Stop here; recover/rebuild the notarized DMG before publishing anything else." >&2
    exit 1
fi
post_push_dmg_sha=$($SHASUM_BIN -a 256 "$DMG_PATH" | $AWK_BIN '{print $1}')
if [ "$post_push_dmg_sha" != "$gate_dmg_sha" ]; then
    echo "  ✗ Release artifact changed during the push/CI gate." >&2
    echo "    Before push: $gate_dmg_sha" >&2
    echo "    After push:  $post_push_dmg_sha" >&2
    echo "    Refusing to upload bytes that did not pass the pre-tag manifest gate." >&2
    exit 1
fi
echo "  ✓ Post-push gate: notarized DMG survived unchanged (${post_push_dmg_sha:0:16}...)"

# Snapshot the exact validated bytes into a private, random path before handing
# a pathname to gh. Re-validating .build and then asking another process to open
# it left a swap window in which different bytes could be uploaded.
DMG_NAME="MacCrab-v$VERSION.dmg"
UPLOAD_SNAPSHOT_DIR=$(/usr/bin/mktemp -d /private/tmp/maccrab-release-upload.XXXXXX)
if ! /bin/chmod 700 "$UPLOAD_SNAPSHOT_DIR"; then
    /bin/rmdir "$UPLOAD_SNAPSHOT_DIR" || true
    UPLOAD_SNAPSHOT_DIR=""
    echo "  ✗ Could not make the release upload snapshot directory private." >&2
    exit 1
fi
UPLOAD_SNAPSHOT="$UPLOAD_SNAPSHOT_DIR/$DMG_NAME"
if ! /bin/cp -p "$BUILD_DMG_PATH" "$UPLOAD_SNAPSHOT"; then
    echo "  ✗ Could not create private release upload snapshot." >&2
    exit 1
fi
/bin/chmod 600 "$UPLOAD_SNAPSHOT"
if ! is_nonempty_regular_release_artifact "$UPLOAD_SNAPSHOT"; then
    echo "  ✗ Private upload snapshot is not a non-empty regular file." >&2
    exit 1
fi
upload_snapshot_sha=$($SHASUM_BIN -a 256 "$UPLOAD_SNAPSHOT" | $AWK_BIN '{print $1}')
if [ "$upload_snapshot_sha" != "$gate_dmg_sha" ]; then
    echo "  ✗ DMG changed while the private upload snapshot was created." >&2
    echo "    Expected: $gate_dmg_sha" >&2
    echo "    Snapshot: $upload_snapshot_sha" >&2
    exit 1
fi
verify_immutable_upload_snapshot() {
    local current_sha
    if ! is_nonempty_regular_release_artifact "$UPLOAD_SNAPSHOT"; then
        echo "CRITICAL: immutable release snapshot disappeared or changed type" >&2
        return 1
    fi
    current_sha=$($SHASUM_BIN -a 256 "$UPLOAD_SNAPSHOT" | $AWK_BIN '{print $1}')
    if [ "$current_sha" != "$gate_dmg_sha" ]; then
        echo "CRITICAL: immutable release snapshot changed during publication" >&2
        return 1
    fi
}

# Create an explicitly owned DRAFT first. GitHub's normal `gh release create`
# publishes after upload, which exposes unverified bytes and makes rollback
# impossible when immutable releases are enabled. A random marker proves which
# draft belongs to this run; after capture, every query/PATCH uses its
# immutable database ID rather than the mutable tag name.
RELEASE_RUN_NONCE=$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]')
RELEASE_DRAFT_TITLE="MacCrab v$VERSION [release-run:$RELEASE_RUN_NONCE]"
RELEASE_FINAL_TITLE="MacCrab v$VERSION"
NOTES_FILE="$RELEASE_METADATA_ROOT/RELEASE_NOTES/v$VERSION.md"
GH_RELEASE_CREATE_ARGS=("v$VERSION" "$UPLOAD_SNAPSHOT" \
    --title "$RELEASE_DRAFT_TITLE" --draft --verify-tag)
if [ "$VERSION_IS_RC" = "1" ]; then
    GH_RELEASE_CREATE_ARGS+=(--prerelease --latest=false)
fi
if [ -f "$NOTES_FILE" ]; then
    GH_RELEASE_CREATE_ARGS+=(--notes-file "$NOTES_FILE")
else
    echo "  ! WARNING: $NOTES_FILE not found — falling back to generated notes." >&2
    GH_RELEASE_CREATE_ARGS+=(--generate-notes)
fi

release_record_by_tag() {
    publisher_gh release view "v$VERSION" --json databaseId,name,isDraft \
        --jq '[.databaseId,.name,.isDraft] | @tsv' 2>/dev/null
}

report_manual_release_recovery() {
    local release_id="${1:-unknown}" title="${2:-unknown}" state="${3:-unknown}"
    echo "    MANUAL RECOVERY REQUIRED: retained GitHub release ID $release_id" >&2
    echo "    title=$title state=$state" >&2
    echo "    inspect: https://github.com/$CANONICAL_GH_REPO/releases" >&2
    echo "    The release pipeline never removes ambiguous or failed remote records automatically." >&2
}

release_create_status=0
if publisher_gh release create "${GH_RELEASE_CREATE_ARGS[@]}"; then
    :
else
    release_create_status=$?
fi

release_record=""
for release_record_attempt in 1 2 3 4 5; do
    release_record=$(release_record_by_tag || true)
    [ -n "$release_record" ] && break
    [ "$release_record_attempt" = "5" ] || sleep 2
done
IFS=$'\t' read -r observed_release_id observed_release_name observed_release_draft \
    <<< "$release_record"

if [ "$release_create_status" -ne 0 ]; then
    echo "  ✗ GitHub draft creation/upload failed (exit $release_create_status)." >&2
    if [[ "${observed_release_id:-}" =~ ^[0-9]+$ ]] \
            && [ "${observed_release_name:-}" = "$RELEASE_DRAFT_TITLE" ] \
            && [ "${observed_release_draft:-}" = "true" ]; then
        report_manual_release_recovery "$observed_release_id" "$observed_release_name" draft
    elif [ -n "${observed_release_id:-}" ]; then
        echo "    A release exists for the tag but lacks this run's nonce; leaving unowned ID $observed_release_id untouched." >&2
        report_manual_release_recovery "$observed_release_id" "${observed_release_name:-unknown}" \
            "draft=${observed_release_draft:-unknown}"
    else
        echo "    No owned draft became visible; inspect the canonical releases page before retrying." >&2
    fi
    exit 1
fi

if ! [[ "${observed_release_id:-}" =~ ^[0-9]+$ ]] \
        || [ "${observed_release_name:-}" != "$RELEASE_DRAFT_TITLE" ] \
        || [ "${observed_release_draft:-}" != "true" ]; then
    echo "CRITICAL: create returned success but the nonce-marked draft could not be identified." >&2
    report_manual_release_recovery "${observed_release_id:-unknown}" \
        "${observed_release_name:-unknown}" "draft=${observed_release_draft:-unknown}"
    exit 1
fi
OWNED_RELEASE_ID="$observed_release_id"

# Verify the exact owned draft, named asset, and still-current remote tag before
# making any bytes public.
remote_upload_sha=""
for remote_digest_attempt in 1 2 3 4 5; do
    remote_upload_sha=$(publisher_gh api \
        "repos/$CANONICAL_GH_REPO/releases/$OWNED_RELEASE_ID" \
        --jq ".assets[] | select(.name == \"$DMG_NAME\") | .digest" \
        2>/dev/null | $SED_BIN -n 's/^sha256://p' | /usr/bin/head -1 || true)
    [ "$remote_upload_sha" = "$gate_dmg_sha" ] && break
    [ -n "$remote_upload_sha" ] && break
    [ "$remote_digest_attempt" = "5" ] || sleep 2
done
remote_tag_object=$($GIT_BIN ls-remote origin "refs/tags/v$VERSION" | $AWK_BIN 'NR == 1 {print $1}')
if [ "$remote_upload_sha" != "$gate_dmg_sha" ] \
        || [ "$remote_tag_object" != "$TAG_OBJECT" ]; then
    echo "  ✗ Owned draft failed asset or tag verification." >&2
    echo "    Expected asset: $gate_dmg_sha" >&2
    echo "    Draft asset:    ${remote_upload_sha:-<missing>}" >&2
    echo "    Expected tag:   $TAG_OBJECT" >&2
    echo "    Remote tag:     ${remote_tag_object:-<missing>}" >&2
    report_manual_release_recovery "$OWNED_RELEASE_ID" "$RELEASE_DRAFT_TITLE" draft
    exit 1
fi
echo "  ✓ Draft asset digest and remote tag verified (${remote_upload_sha:0:16}...)"

if [ "$VERSION_IS_RC" = "1" ]; then
    RELEASE_PRERELEASE=true
    RELEASE_MAKE_LATEST=false
else
    RELEASE_PRERELEASE=false
    RELEASE_MAKE_LATEST=true
fi
publish_status=0
if publisher_gh api -X PATCH "repos/$CANONICAL_GH_REPO/releases/$OWNED_RELEASE_ID" \
        -f "name=$RELEASE_FINAL_TITLE" \
        -F "draft=false" \
        -F "prerelease=$RELEASE_PRERELEASE" \
        -f "make_latest=$RELEASE_MAKE_LATEST" >/dev/null; then
    :
else
    publish_status=$?
fi

published_record=$(publisher_gh api \
    "repos/$CANONICAL_GH_REPO/releases/$OWNED_RELEASE_ID" \
    --jq '[.id,.name,.draft,.prerelease,.tag_name,.html_url] | @tsv' \
    2>/dev/null || true)
IFS=$'\t' read -r published_id published_name published_draft \
    published_prerelease published_tag PUBLISHED_RELEASE_URL <<< "$published_record"
published_upload_sha=$(publisher_gh api \
    "repos/$CANONICAL_GH_REPO/releases/$OWNED_RELEASE_ID" \
    --jq ".assets[] | select(.name == \"$DMG_NAME\") | .digest" \
    2>/dev/null | $SED_BIN -n 's/^sha256://p' | /usr/bin/head -1 || true)
published_remote_tag_object=$($GIT_BIN ls-remote origin "refs/tags/v$VERSION" | $AWK_BIN 'NR == 1 {print $1}')
if [ "$published_id" != "$OWNED_RELEASE_ID" ] \
        || [ "$published_name" != "$RELEASE_FINAL_TITLE" ] \
        || [ "$published_draft" != "false" ] \
        || [ "$published_prerelease" != "$RELEASE_PRERELEASE" ] \
        || [ "$published_tag" != "v$VERSION" ] \
        || [ "$published_upload_sha" != "$gate_dmg_sha" ] \
        || [ "$published_remote_tag_object" != "$TAG_OBJECT" ]; then
    echo "CRITICAL: exact release ID $OWNED_RELEASE_ID was not verified published (PATCH exit $publish_status)." >&2
    echo "    Publication state is ambiguous; leaving it untouched for manual inspection." >&2
    report_manual_release_recovery "$OWNED_RELEASE_ID" \
        "${published_name:-$RELEASE_DRAFT_TITLE}" "draft=${published_draft:-unknown}"
    exit 1
fi

echo ""
echo "  ✓ Verified GitHub release published: ${PUBLISHED_RELEASE_URL:-https://github.com/peterhanily/maccrab/releases/tag/v$VERSION} (ID $OWNED_RELEASE_ID)"
verify_immutable_upload_snapshot
if [ "$VERSION_IS_RC" = "1" ]; then
    echo ""
    echo "═══════════════════════════════════════"
    echo "  MacCrab v$VERSION Prerelease Published"
    echo "═══════════════════════════════════════"
    echo "  Production appcast, release.json, and Homebrew casks were not published."
    exit 0
fi

# Step 6: Generate the appcast entry. Pre-fix this script stopped after
# `gh release create` and the operator had to remember to run
# generate-appcast-entry.sh + publish-appcast-entry.sh manually. The
# procedural gap meant several point releases shipped to GitHub but
# never reached existing users' Sparkle clients. Now: always try.
# SKIP_APPCAST=1 skips only the Sparkle feed. It does not skip release.json,
# live SHA verification, or the Homebrew tap: release.sh has already published
# a public GitHub tag/asset, so those surfaces must not be reported complete
# while serving an older version.
SITE_REPO="${SITE_REPO:-peterhanily/maccrab-site}"
APPCAST_ITEM=""
keep_appcast_item=0
# A failed site publish is retried by hand with the same release.json. A resumed
# release's copy comes from the tag's commit into a private directory removed on
# exit, and the checkout may hold different bytes, so that copy is kept instead.
site_recovery_release_json=release.json
SITE_PUBLISH_ARGS=(--release-json "$RELEASE_METADATA_ROOT/release.json" --site-repo "$SITE_REPO" --version "$VERSION")
if [ "${SKIP_APPCAST:-0}" = "1" ]; then
    echo ""
    echo "  Step 6/6: Skipping appcast publish (SKIP_APPCAST=1)"
    SITE_PUBLISH_ARGS+=(--skip-appcast)
else
    echo ""
    echo "Step 6/6: Generating appcast entry..."
    verify_immutable_upload_snapshot
    APPCAST_ITEM=$(/usr/bin/mktemp /private/tmp/maccrab-appcast-item.XXXXXX)
    APPCAST_ROLLOUT_ARGS=()
    if [ "${MACCRAB_APPCAST_IMMEDIATE:-0}" = "1" ]; then
        APPCAST_ROLLOUT_ARGS+=(--immediate)
    elif [ "${MACCRAB_APPCAST_IMMEDIATE:-0}" = "0" ]; then
        APPCAST_ROLLOUT_ARGS+=(--phased-rollout-interval "${MACCRAB_PHASED_ROLLOUT_INTERVAL:-86400}")
    else
        echo "  ✗ MACCRAB_APPCAST_IMMEDIATE must be 0 or 1" >&2
        exit 2
    fi
    # The generator gets no GitHub/notary credentials. Its only executable
    # dependencies are the checked SwiftPM tools and fixed Apple utilities.
    if /usr/bin/env -i PATH=/usr/bin:/bin HOME="$HOME" TMPDIR=/private/tmp LC_ALL=C LANG=C \
            "$BUILD_WORKSPACE/scripts/generate-appcast-entry.sh" \
            --dmg "$UPLOAD_SNAPSHOT" --version "$VERSION" --build-number "$BUILD_NUMBER" \
            "${APPCAST_ROLLOUT_ARGS[@]}" \
            > "$APPCAST_ITEM"; then
        SITE_PUBLISH_ARGS+=(--item "$APPCAST_ITEM")
    else
        release_fail "appcast generation failed — fix Sparkle sign_update + private key and retry; existing Sparkle users will not receive v$VERSION"
        # release.json still ships alone: the GitHub release is already public.
        rm -f "$APPCAST_ITEM"
        APPCAST_ITEM=""
        SITE_PUBLISH_ARGS+=(--skip-appcast)
    fi
fi

# Step 6b: Publish appcast.xml and release.json to the site in ONE commit.
    # publish-release-json.sh has existed since v1.8 (created exactly
    # to fix a class of v1.7.12 / 929-tests post-release drift bug) but
    # was never wired into release.sh, so https://maccrab.com/release.json
    # silently lagged the actual release every cycle. v1.10.1 closed
    # that gap by adding this step. The site's JSON-LD softwareVersion +
    # the JS-rendered version pill both read this file.
    # The two files used to be two commits seconds apart, and Workers Builds
    # deploys each commit on its own, not necessarily in order: on 2026-09-22
    # the older appcast commit's build started 17 s after the newer
    # release.json commit's build and deployed last, so release.json served
    # 1.22.0 for six days while both steps reported success. One commit, one
    # deploy.
echo ""
if [ -n "$APPCAST_ITEM" ]; then
    echo "Step 6b: Publishing appcast.xml + release.json to the site in one commit..."
else
    echo "Step 6b: Publishing release.json to the site..."
fi
verify_immutable_upload_snapshot
# The publisher receives only the one PAT it needs; Apple credentials,
# other PATs and signing configuration are not inherited.
if SITE_REPO_TOKEN="$MACCRAB_PUBLISH_SITE_REPO_TOKEN" /usr/bin/python3 -I -B -c '
import os, sys
environment = {"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"],
               "TMPDIR": "/private/tmp", "LC_ALL": "C", "LANG": "C",
               "SITE_REPO_TOKEN": os.environ["SITE_REPO_TOKEN"]}
os.execve(sys.argv[1], sys.argv[1:], environment)
' "$BUILD_WORKSPACE/scripts/publish-site-release.sh" "${SITE_PUBLISH_ARGS[@]}"; then
        echo "  ✓ Site commit landed; waiting for maccrab.com to serve it"
        # Verify the LIVE files, not the commit or the local copy. Step 6c below
        # only ever reads ./release.json, which always agrees with itself, and a
        # landed commit proves nothing about which deploy is serving. Poll until
        # the site serves BOTH the new Sparkle build and the new version + DMG
        # sha256. A fresh query string per attempt keeps a CDN cache from
        # answering for the site.
        published_ok=0
        live_ver=""
        live_sha=""
        live_appcast_ok=0
        for attempt in $(seq 1 12); do
            cache_bust="release-check=${BUILD_NUMBER}-$(/bin/date +%s)-${attempt}"
            live=$($CURL_BIN -fsS --max-time 10 "https://maccrab.com/release.json?${cache_bust}" 2>/dev/null || true)
            live_ver=$(printf '%s' "$live" | $GREP_BIN -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | /usr/bin/head -1 | $SED_BIN -E 's/.*"([^"]+)"$/\1/' || true)
            live_sha=$(printf '%s' "$live" | $GREP_BIN -oE '"sha256"[[:space:]]*:[[:space:]]*"[a-f0-9]{64}"' | /usr/bin/head -1 | $GREP_BIN -oE '[a-f0-9]{64}' || true)
            live_appcast_ok=1
            if [ -n "$APPCAST_ITEM" ]; then
                live_appcast=$($CURL_BIN -fsS --max-time 10 "https://maccrab.com/appcast.xml?${cache_bust}" 2>/dev/null || true)
                case "$live_appcast" in
                    *"<sparkle:version>${BUILD_NUMBER}</sparkle:version>"*) ;;
                    *) live_appcast_ok=0 ;;
                esac
            fi
            if [ "$live_ver" = "$VERSION" ] && [ "$live_sha" = "$SHA" ] && [ "$live_appcast_ok" = "1" ]; then
                published_ok=1
                break
            fi
            sleep 10
        done
        if [ "$published_ok" = "1" ]; then
            echo "  ✓ https://maccrab.com/release.json serves v$VERSION / sha ${SHA:0:16}..."
            [ -z "$APPCAST_ITEM" ] \
                || echo "  ✓ https://maccrab.com/appcast.xml offers Sparkle build $BUILD_NUMBER to existing users"
        else
            if [ "$live_ver" != "$VERSION" ] || [ "$live_sha" != "$SHA" ]; then
                release_fail "maccrab.com/release.json still does not serve v$VERSION + sha ${SHA:0:16}... after ~2min although the site commit landed (live: version=${live_ver:-<unreadable>} sha=${live_sha:0:16}) — the site is advertising a DIFFERENT build's hash to anyone verifying their download. Redeploy $SITE_REPO main in Cloudflare Workers Builds and re-check with: curl -s \"https://maccrab.com/release.json?nocache=\$(date +%s)\""
            fi
            if [ "$live_appcast_ok" != "1" ]; then
                release_fail "maccrab.com/appcast.xml still does not offer Sparkle build $BUILD_NUMBER after ~2min although the site commit landed — existing Sparkle users will not receive v$VERSION. Redeploy $SITE_REPO main in Cloudflare Workers Builds and re-check with: curl -s \"https://maccrab.com/appcast.xml?nocache=\$(date +%s)\" | grep sparkle:version"
            fi
        fi
    else
        if [ "$RESUME_PUBLISH" = "1" ]; then
            site_recovery_release_json="$RESUME_METADATA_DIR/release.json"
            RESUME_METADATA_DIR=""
        fi
        if [ -n "$APPCAST_ITEM" ]; then
            keep_appcast_item=1
            release_fail "site publish failed — appcast.xml and release.json are published together or not at all; existing Sparkle users will not receive v$VERSION and maccrab.com advertises the PREVIOUS release until it lands. The generated item remains at $APPCAST_ITEM; after fixing the cause rerun, with the publisher profile loaded as in docs/ROLLBACK_RUNBOOK.md (never a token on the command line), 'scripts/publish-site-release.sh --item $APPCAST_ITEM --release-json $site_recovery_release_json --site-repo $SITE_REPO --version $VERSION'"
        else
            release_fail "release.json publish failed — maccrab.com is still advertising the PREVIOUS release; after fixing the cause rerun, with the publisher profile loaded as in docs/ROLLBACK_RUNBOOK.md (never a token on the command line), 'scripts/publish-site-release.sh --skip-appcast --release-json $site_recovery_release_json --site-repo $SITE_REPO --version $VERSION'"
        fi
    fi
if [ -n "$APPCAST_ITEM" ]; then
    if [ "$keep_appcast_item" = "0" ]; then
        rm -f "$APPCAST_ITEM"
    else
        echo "  ! Appcast recovery item retained: $APPCAST_ITEM" >&2
    fi
fi

    # Step 6c: Cross-source SHA sanity check. v1.12.7 shipped with
    # release.json's SHA pointing at RC2's DMG (96d408db...) while
    # the GitHub release asset and Casks/maccrab.rb correctly pointed
    # at RC3's DMG (7c862c29...) — the squash-merge flow had restored
    # a pre-RC3 release.json snapshot and nobody noticed until a
    # post-publish manual check. v1.12.8 codifies the check: after
    # both publish steps land, diff the three sources of truth for
    # the DMG SHA. Three sources must agree:
    #   1. release.json on the local repo (just pushed to site)
    #   2. Casks/maccrab.rb (just bumped + pushed)
    #   3. GitHub release asset's recorded digest
    # If any disagree, the release is internally inconsistent and
    # users may end up with conflicting integrity signals.
    echo ""
    echo "Step 6c: Cross-source SHA sanity check..."
    # || true so set -e + pipefail don't abort the post-publish step
    # when grep finds nothing (we WANT to fall through and report).
    local_release_sha=$($GREP_BIN -oE '"sha256":\s*"[a-f0-9]{64}"' "$RELEASE_METADATA_ROOT/release.json" 2>/dev/null | /usr/bin/head -1 | $GREP_BIN -oE '[a-f0-9]{64}' || true)
    cask_sha=$($GREP_BIN -oE 'sha256\s+"[a-f0-9]{64}"' "$RELEASE_METADATA_ROOT/Casks/maccrab.rb" 2>/dev/null | /usr/bin/head -1 | $GREP_BIN -oE '[a-f0-9]{64}' || true)
    gh_release_sha=$(publisher_gh api \
        "repos/$CANONICAL_GH_REPO/releases/$OWNED_RELEASE_ID" \
        --jq ".assets[] | select(.name == \"$DMG_NAME\") | .digest" \
        2>/dev/null | $SED_BIN -n 's/^sha256://p' | /usr/bin/head -1 || true)

    cross_check_ok=1
    if [ -z "$local_release_sha" ] || [ -z "$cask_sha" ] || [ -z "$gh_release_sha" ]; then
        # "Could not read" is not a benign outcome: it is precisely the state in
        # which divergence is invisible. Pre-fix this only suppressed a ✓ and the
        # release still exited 0.
        release_fail "could not read all three SHAs (release.json=$local_release_sha cask=$cask_sha gh=$gh_release_sha) — verify by hand before announcing"
        cross_check_ok=0
    elif [ "$local_release_sha" != "$cask_sha" ] || [ "$cask_sha" != "$gh_release_sha" ]; then
        echo "      release.json:      $local_release_sha" >&2
        echo "      Casks/maccrab.rb:  $cask_sha" >&2
        echo "      GH release asset:  $gh_release_sha" >&2
        release_fail "SHA MISMATCH — the published artifact is internally inconsistent; users will fail integrity verification against at least one of the three. Republish the lagging file with the correct SHA."
        cross_check_ok=0
    fi
    if [ "$cross_check_ok" = "1" ]; then
        echo "  ✓ release.json, Casks/maccrab.rb, and GitHub release all agree on SHA ${local_release_sha:0:16}..."
    fi

    # Step 6d: Publish the validated cask to the dedicated, append-only tap
    # repo (peterhanily/homebrew-maccrab) via the GitHub Contents API. New
    # users install with the one-liner
    #   brew install --cask peterhanily/maccrab/maccrab
    # which auto-taps that repo. Contents-API publishing is forward-only (one
    # clean commit, never a force-push), so `brew update` always fast-forwards
    # — unlike the old app-repo-as-tap, whose rewritten history poisoned every
    # existing clone with rebase conflicts. Token needs write on the tap repo.
    echo ""
    echo "Step 6d: Publishing cask to homebrew-maccrab tap..."
    verify_immutable_upload_snapshot
    if TAP_REPO_TOKEN="$MACCRAB_PUBLISH_TAP_REPO_TOKEN" \
            CASK_PATH="$RELEASE_METADATA_ROOT/Casks/maccrab.rb" \
            "$BUILD_WORKSPACE/scripts/publish-cask.sh"; then
        echo "  ✓ Cask published; 'brew install --cask peterhanily/maccrab/maccrab' serves v$VERSION"
else
    release_fail "cask publish failed — set TAP_REPO_TOKEN (PAT with contents:write on peterhanily/homebrew-maccrab) then run 'scripts/publish-cask.sh' manually; Homebrew users will not receive v$VERSION"
fi

echo ""
verify_immutable_upload_snapshot
# The release is only "released" if every publish step landed. Pre-fix this
# banner printed unconditionally and the script exited 0 even when the appcast,
# release.json, the cross-source SHA check and the tap cask had all failed —
# so a half-published release looked identical to a good one.
if [ "$RELEASE_FAILURE_COUNT" -gt 0 ]; then
    echo "═══════════════════════════════════════"
    echo "  MacCrab v$VERSION — RELEASE INCOMPLETE"
    echo "═══════════════════════════════════════"
    echo ""
    echo "  The DMG was built and uploaded (.build/MacCrab-v$VERSION.dmg) but"
    echo "  $RELEASE_FAILURE_COUNT publish step(s) did not land. Users are NOT fully served:"
    printf '%s' "$RELEASE_FAILURES"
    echo ""
    echo "  Fix each item above, re-run the named script, then re-verify:"
    echo "    verified GitHub release remains published: ${PUBLISHED_RELEASE_URL:-<unknown>} (ID $OWNED_RELEASE_ID)"
    echo "    It is intentionally not rolled back: the asset was verified before publication"
    echo "    and immutable-release policy may prohibit deletion."
    echo "    curl -s https://maccrab.com/release.json"
    echo "    curl -s https://maccrab.com/appcast.xml | grep sparkle:version"
    exit 1
fi
echo "═══════════════════════════════════════"
echo "  MacCrab v$VERSION Released!"
echo "═══════════════════════════════════════"
echo ""
echo "  DMG: .build/MacCrab-v$VERSION.dmg"
echo ""
echo "  Users can install with:"
echo "    brew install --cask peterhanily/maccrab/maccrab"
echo ""
