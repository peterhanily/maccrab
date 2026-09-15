#!/bin/bash
# Disable tracing before any credential or private build-input expansion.
set +x
# build-release.sh — Build MacCrab.app with embedded ES system extension.
#
# v1.3.0 architectural shift: the daemon that previously ran as a
# standalone LaunchDaemon is now a proper .systemextension bundle
# embedded inside MacCrab.app. Apple's AMFI rejects ES entitlements
# on LaunchDaemon Mach-Os regardless of signing correctness — only
# binaries loaded via OSSystemExtensionRequest can use ES.
#
# Resulting DMG contains:
#   MacCrab.app/
#     Contents/
#       Info.plist                          (app metadata + NSSystemExtensionUsageDescription)
#       embedded.provisionprofile           (Developer ID profile, team + ES grant)
#       MacOS/MacCrab                       (dashboard + activator, signed with system-extension.install)
#       Resources/AppIcon.icns
#       Library/SystemExtensions/
#         com.maccrab.agent.systemextension/
#           Contents/
#             Info.plist                    (SYEX package, NSSystemExtensionPointIdentifier=endpoint_security)
#             embedded.provisionprofile     (same profile)
#             MacOS/com.maccrab.agent       (ES daemon, signed with ES entitlement)
#             _CodeSignature/CodeResources
#       Resources/bin/maccrabctl             (CLI tool, hardened runtime, no entitlements)
#       Resources/bin/maccrab-mcp            (MCP server, hardened runtime, no entitlements)
#       Resources/compiled_rules/*.json      (signed built-in detection corpus)
#   install.sh                               (manual privileged installer)
#
# ─── Composable stages (v1.19.0 / S5-T6) ─────────────────────────────
# The release build is decomposed into four ordered stages that can be
# run individually OR as one non-interactive flow. The default (no
# argument) runs every stage in order in a single process with a
# per-PID staging dir — byte-for-byte identical to the pre-S5-T6 linear
# script. Individual stage invocation remains useful for local diagnosis and
# reproducibility checks; signing stays on the trusted Mac. This repository has
# no hosted release workflow.
#
#   scripts/build-release.sh                   # all four stages (default)
#   scripts/build-release.sh all               # explicit equivalent
#   scripts/build-release.sh unsigned-build    # stage 1: compile + rules + manifest
#   scripts/build-release.sh assemble          # stage 2: .app + sysext bundle layout
#   scripts/build-release.sh sign              # stage 3: codesign + Sparkle embed + guards
#   scripts/build-release.sh publish           # stage 4: DMG + notarize (+ GA metadata)
#
# Stage handoff: in single-stage mode the staging tree persists at a
# DETERMINISTIC path ($PROJECT_DIR/.build/maccrab-stage) so stage N can
# pick up where stage N-1 left off across separate process invocations.
# In all-stages mode it lives under /tmp/maccrab-release-$$ and is
# trap-cleaned on exit, exactly as before. Every stage is idempotent
# enough to re-run; `unsigned-build` resets the staging tree.

set -euo pipefail

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
SCRIPT_DIR="$(cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)"
PROJECT_DIR="$(/usr/bin/dirname "$SCRIPT_DIR")"
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
    GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE GIT_PREFIX GIT_CONFIG \
    GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM GIT_CONFIG_COUNT \
    GIT_CONFIG_PARAMETERS GIT_EXEC_PATH GIT_CEILING_DIRECTORIES \
    GIT_DISCOVERY_ACROSS_FILESYSTEM
GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_REPLACE_OBJECTS
GIT_BIN=/usr/bin/git
SWIFT_BIN=/usr/bin/swift
CODESIGN_BIN=/usr/bin/codesign
SECURITY_BIN=/usr/bin/security
SHASUM_BIN=/usr/bin/shasum
XCODEBUILD_BIN=/usr/bin/xcodebuild
XCRUN_BIN=/usr/bin/xcrun
SPCTL_BIN=/usr/sbin/spctl
for required_tool in "$GIT_BIN" "$SWIFT_BIN" "$CODESIGN_BIN" "$SECURITY_BIN" \
        "$SHASUM_BIN" "$XCODEBUILD_BIN" "$XCRUN_BIN" "$SPCTL_BIN"; do
    if [ ! -x "$required_tool" ]; then
        echo "ERROR: fixed release tool is unavailable: $required_tool" >&2
        exit 1
    fi
done
# Trusted parser library. It reads env files as allowlisted data; external env
# files and inter-stage state are never shell-sourced.
# shellcheck source=scripts/release-env.sh
source "$SCRIPT_DIR/release-env.sh"

# Credentials may arrive through the invoking environment, but unsigned Swift
# builds, package plugins, rule compilation, and assembly must never inherit
# them. Preserve explicit caller overrides only as unexported shell variables;
# the fixed signing/notary phase reintroduces the minimum values deliberately.
unset MACCRAB_CALLER_DEVELOPER_ID MACCRAB_CALLER_APPLE_ID \
    MACCRAB_CALLER_APPLE_TEAM_ID MACCRAB_CALLER_NOTARIZE_PASSWORD \
    MACCRAB_CALLER_NOTARIZE_KEYCHAIN_PROFILE
MACCRAB_CALLER_DEVELOPER_ID="${DEVELOPER_ID:-}"
MACCRAB_CALLER_APPLE_ID="${APPLE_ID:-}"
MACCRAB_CALLER_APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
MACCRAB_CALLER_NOTARIZE_PASSWORD="${NOTARIZE_PASSWORD:-}"
MACCRAB_CALLER_NOTARIZE_KEYCHAIN_PROFILE="${NOTARIZE_KEYCHAIN_PROFILE:-}"
unset_maccrab_signing_env
unset_maccrab_publisher_env

# ─── Stage selection ─────────────────────────────────────────────────
# First positional arg selects the stage. Absent / "all" runs the full
# ordered pipeline in one process (the historical behavior). Any other
# value runs exactly that one stage against the persisted staging tree.
STAGE="${1:-all}"
case "$STAGE" in
    all|unsigned-build|assemble|sign|publish) ;;
    -h|--help|help)
        sed -n '/^# ─── Composable stages/,/resets the staging tree\./p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "ERROR: unknown stage '$STAGE'. Valid: all | unsigned-build | assemble | sign | publish" >&2
        exit 2
        ;;
esac

# Default to the latest annotated git tag (strip leading 'v') so
# we never accidentally ship MacCrab-v1.0.0.dmg when the operator
# forgets to pass VERSION=. Falls back to 1.0.0 only if there are
# no tags at all (fresh clone, dev sandbox).
if [ -n "${VERSION:-}" ]; then
    DEFAULT_VERSION=$VERSION
elif [ "${MACCRAB_TRACKED_EXPORT:-0}" = "1" ]; then
    echo "ERROR: tracked-only release builds require an explicit VERSION" >&2
    exit 2
else
    DEFAULT_VERSION="$(cd "$PROJECT_DIR" && $GIT_BIN describe --tags --abbrev=0 2>/dev/null | /usr/bin/sed 's/^v//')"
fi
VERSION="${VERSION:-${DEFAULT_VERSION:-1.0.0}}"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
    echo "ERROR: VERSION must be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-rc.N" >&2
    exit 2
fi

# v1.10.0 audit fix: derive a unique CFBundleVersion (build number)
# per build so sysextd can tell two builds of the same VERSION apart
# and actually replaces the cached binary. macOS sysextd compares
# (team-id, bundle-id, CFBundleShortVersionString, CFBundleVersion)
# tuples — if all four match, an activation request short-circuits
# even when the on-disk bundle bytes have changed. Field-observed:
# rebuilding 1.10.0 with code changes left the OLD binary running
# because both tuples said `1.10.0/1.10.0`. The build number is
# `<numeric-version>.<unix-time>` so every rebuild is distinct; the
# user-visible marketing version (CFBundleShortVersionString) stays
# clean. Caller can override with `BUILD_NUMBER=<custom>`: release.sh
# (v1.18+) exports a DETERMINISTIC `<numeric-version>.<commit-count>` so an
# identical rebuild reuses the same tuple and doesn't orphan a new
# reboot-pending sysext zombie. The per-second epoch below is the DEV-loop
# fallback (make dev / standalone build-release.sh): there you rebuild the
# same VERSION with changed code, so a distinct tuple each time is REQUIRED
# to force sysextd to swap the active extension.
#
# v1.19.0 (S5-T6): when running individual stages, the BUILD_NUMBER must
# be IDENTICAL across `assemble` and `sign`/`publish` (the Info.plist
# stamped in assemble must match the bundle that gets signed). A
# per-second epoch computed fresh in each stage process would drift.
# So stage mode persists BUILD_NUMBER into the staging dir during
# unsigned-build and re-reads it in later stages.
# Sparkle stops comparing at a dash. Keep -rc.N only in the marketing
# version; otherwise the commit count is ignored and an RC can sort below
# an installed numeric build of the same base version.
BUILD_VERSION_BASE="${VERSION%%-rc.*}"
if [ -z "${BUILD_NUMBER:-}" ]; then
    export BUILD_NUMBER="${BUILD_VERSION_BASE}.$(date +%s)"
fi
validate_build_number() {
    local numeric_version="${VERSION%%-rc.*}"
    if ! [[ "$BUILD_NUMBER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[1-9][0-9]*$ ]] \
        || [[ "$BUILD_NUMBER" != "$numeric_version".* ]]; then
        echo "ERROR: BUILD_NUMBER must be $numeric_version.<positive numeric revision>: $BUILD_NUMBER" >&2
        exit 2
    fi
}
validate_build_number

# Build channel. `release` is the default and reproduces the historical
# behaviour exactly; `dev` marks a candidate built for the assurance lab.
#
# Two things hang off this:
#   1. The channel is stamped into BOTH Info.plists, so the artifact is
#      self-describing. Anything downstream that must not confuse a dev
#      candidate with a shipped build (the lab's candidate-identity check,
#      an FP corpus deciding whether a host's data counts) reads one key
#      instead of inferring from a version string.
#   2. Sparkle automatic update checks are DISABLED on `dev`. A dev
#      candidate carries the production SUFeedURL, so with checks left on
#      it would quietly update itself to the current public release
#      mid-experiment — and the resulting identity mismatch would surface
#      as a product failure that is really a build-lane defect.
CHANNEL="${MACCRAB_BUILD_CHANNEL:-release}"
case "$CHANNEL" in
    release|dev) ;;
    *) echo "ERROR: MACCRAB_BUILD_CHANNEL must be 'release' or 'dev' (got '$CHANNEL')" >&2; exit 1 ;;
esac
export MACCRAB_BUILD_CHANNEL="$CHANNEL"
if [ "$CHANNEL" = "dev" ]; then SU_AUTOCHECK="false"; else SU_AUTOCHECK="true"; fi

BUILD_DIR="$PROJECT_DIR/.build/release"

# The publish stage owns two transient disk-image paths.  Keep their exact
# values empty until this invocation creates them: the global EXIT handler may
# then clean an interrupted attach/copy/convert without ever guessing at a
# mountpoint or touching the successful, read-only DMG artifact.
# BEGIN RELEASE_DMG_EXIT_CLEANUP
RELEASE_DMG_MOUNT_PATH=""
RELEASE_RW_DMG_PATH=""
RELEASE_DMG_ATTACH_ATTEMPTED=0
RELEASE_CLEAN_STAGING_ON_EXIT=0

cleanup_release_dmg_working_state() {
    # Set ATTACH_ATTEMPTED immediately before hdiutil attach.  This covers an
    # interrupt during attach while still constraining detach to the exact
    # private mktemp directory created by this process.
    if [ "$RELEASE_DMG_ATTACH_ATTEMPTED" = "1" ] \
            && [ -n "$RELEASE_DMG_MOUNT_PATH" ]; then
        /usr/bin/hdiutil detach "$RELEASE_DMG_MOUNT_PATH" -force \
            >/dev/null 2>&1 || true
        RELEASE_DMG_ATTACH_ATTEMPTED=0
    fi
    if [ -n "$RELEASE_DMG_MOUNT_PATH" ]; then
        /bin/rmdir "$RELEASE_DMG_MOUNT_PATH" >/dev/null 2>&1 || true
        RELEASE_DMG_MOUNT_PATH=""
    fi
    if [ -n "$RELEASE_RW_DMG_PATH" ]; then
        /bin/rm -f "$RELEASE_RW_DMG_PATH" >/dev/null 2>&1 || true
        RELEASE_RW_DMG_PATH=""
    fi
}

cleanup_release_build() {
    exit_status=$?
    trap - EXIT
    cleanup_release_dmg_working_state
    if [ "$RELEASE_CLEAN_STAGING_ON_EXIT" = "1" ]; then
        /bin/rm -rf "$STAGING_DIR" >/dev/null 2>&1 || true
    fi
    exit "$exit_status"
}
# END RELEASE_DMG_EXIT_CLEANUP

# BEGIN BARE_TOOL_RELEASE_GUARDS
# Bare executables cannot inherit the outer app's provisioning profile. Giving
# one a restricted entitlement (including keychain-access-groups) makes AMFI
# reject it before main with Code=-413 even though codesign/notarization pass.
# Keep signing and verification centralized so loose and in-app copies cannot
# drift back to different capability sets.
sign_bare_tool() {
    local tool="$1"
    local identity="$2"
    local name
    name=$(/usr/bin/basename "$tool")
    case "$name" in
        maccrabctl|maccrab-mcp) ;;
        *)
            echo "ERROR: refusing bare-tool signing contract for unexpected executable: $tool" >&2
            return 1
            ;;
    esac
    "$CODESIGN_BIN" --sign "$identity" \
        --identifier "com.maccrab.$name" \
        --options runtime \
        --timestamp \
        --force \
        "$tool"
}

verify_bare_tool_signature_contract() {
    local tool="$1"
    local name expected_identifier archs arch metadata entitlements
    name=$(/usr/bin/basename "$tool")
    case "$name" in
        maccrabctl|maccrab-mcp) ;;
        *)
            echo "    ✗ unexpected bare tool in signature guard: $tool" >&2
            return 1
            ;;
    esac
    if [ ! -x "$tool" ] || [ -L "$tool" ]; then
        echo "    ✗ missing, non-executable, or linked bare tool: $tool" >&2
        return 1
    fi
    if ! archs=$(/usr/bin/lipo -archs "$tool" 2>/dev/null) || [ -z "$archs" ]; then
        echo "    ✗ cannot inspect Mach-O slices for bare tool: $tool" >&2
        return 1
    fi
    expected_identifier="com.maccrab.$name"
    for arch in $archs; do
        if ! metadata=$("$CODESIGN_BIN" -dvv --arch "$arch" "$tool" 2>&1); then
            echo "    ✗ cannot inspect $arch signature for bare tool: $tool" >&2
            return 1
        fi
        if ! /usr/bin/grep -Fqx "Identifier=$expected_identifier" <<<"$metadata"; then
            echo "    ✗ $name ($arch) lacks stable identifier $expected_identifier: $tool" >&2
            return 1
        fi
        if ! /usr/bin/grep -Eq '^CodeDirectory .*flags=.*\([^)]*runtime' <<<"$metadata"; then
            echo "    ✗ $name ($arch) lacks hardened runtime: $tool" >&2
            return 1
        fi
        if ! entitlements=$("$CODESIGN_BIN" -d --arch "$arch" --entitlements - "$tool" 2>&1); then
            echo "    ✗ cannot inspect $arch entitlements for bare tool: $tool" >&2
            return 1
        fi
        # Xcode 27 prints a [Key] tree; older codesign emits XML <key> nodes.
        # Zero keys is deliberate: any restricted key would require a matching
        # per-tool provisioning profile/bundle and can turn a valid signature
        # into a launch-time AMFI kill.
        if /usr/bin/grep -Eq '\[Key\]|<key>' <<<"$entitlements"; then
            echo "    ✗ $name ($arch) carries forbidden bare-tool entitlements: $tool" >&2
            /usr/bin/grep -E '\[Key\]|<key>' <<<"$entitlements" >&2 || true
            return 1
        fi
    done
}

verify_bare_tool_runtime() {
    local app="$1"
    local phase="$2"
    local ctl="$app/Contents/Resources/bin/maccrabctl"
    local mcp="$app/Contents/Resources/bin/maccrab-mcp"
    local output status

    if output=$("$ctl" version 2>&1); then
        :
    else
        status=$?
        echo "ERROR: $phase maccrabctl runtime probe exited $status: $output" >&2
        return 1
    fi
    if ! /usr/bin/grep -Fqx "MacCrab Detection Engine v$VERSION" <<<"$output"; then
        echo "ERROR: $phase maccrabctl runtime probe returned the wrong version:" >&2
        printf '%s\n' "$output" >&2
        return 1
    fi

    if output=$("$mcp" --version 2>&1); then
        :
    else
        status=$?
        echo "ERROR: $phase maccrab-mcp runtime probe exited $status: $output" >&2
        return 1
    fi
    if [ "$output" != "maccrab-mcp $VERSION" ]; then
        echo "ERROR: $phase maccrab-mcp runtime probe returned the wrong version:" >&2
        printf '%s\n' "$output" >&2
        return 1
    fi
    echo "    ✓ $phase bare tools launch under AMFI and report v$VERSION"
}

# The exec probe above proves maccrabctl/maccrab-mcp are allowed to run — but
# `verify_bare_tool_entitlements` asserts those two carry ZERO entitlements, so
# they are the least entitlement-sensitive binaries in the payload. The rc.3-rc.5
# escape was an AMFI kill from a provisioning-profile/entitlement mismatch, and
# the two components that can actually suffer that class — MacCrabApp
# (system-extension.install) and the sysext (endpoint-security.client) — cannot
# be exec-probed at all: one is a GUI app, the other only ever runs when sysextd
# spawns it. So verify the invariant statically instead of hoping an exec
# surfaces it. Every restricted entitlement a binary requests must be granted by
# the provisioning profile embedded beside it; when it is not, AMFI kills the
# process at exec and no amount of `codesign --verify` sees it coming.
plist_dict_keys() {
    /usr/bin/plutil -p - | /usr/bin/sed -n 's/^  "\([^"]*\)" =>.*/\1/p'
}

# plutil treats `.` as a keypath separator, and every restricted entitlement key
# is dotted. Escape them so `com.apple.developer.x` is one key, not five levels.
plist_escape_keypath() {
    printf '%s' "$1" | /usr/bin/sed 's/\./\\./g'
}

# Pure comparison half: takes the two decoded plists as strings so a fixture can
# drive both the accepting and the refusing path without a signed bundle.
verify_entitlement_coverage_plists() {
    local ent="$1" prof="$2" name="$3"
    local key kp bin_val prof_val count i j elem covered pattern prefix

    while IFS= read -r key; do
        [ -n "$key" ] || continue
        case "$key" in
            com.apple.developer.*|com.apple.application-identifier|keychain-access-groups) ;;
            *) continue ;;
        esac
        kp=$(plist_escape_keypath "$key")
        if ! prof_val=$(printf '%s' "$prof" | /usr/bin/plutil -extract "$kp" raw -o - - 2>/dev/null); then
            echo "ERROR: $name requests restricted entitlement '$key' that its embedded" >&2
            echo "       provisioning profile does not grant — AMFI kills this at exec." >&2
            return 1
        fi
        bin_val=$(printf '%s' "$ent" | /usr/bin/plutil -extract "$kp" raw -o - - 2>/dev/null || true)
        if [ "$key" = "keychain-access-groups" ]; then
            count=$bin_val
            i=0
            while [ "$i" -lt "${count:-0}" ]; do
                elem=$(printf '%s' "$ent" | /usr/bin/plutil -extract "$kp.$i" raw -o - -)
                covered=0
                j=0
                while [ "$j" -lt "${prof_val:-0}" ]; do
                    pattern=$(printf '%s' "$prof" | /usr/bin/plutil -extract "$kp.$j" raw -o - -)
                    case "$pattern" in
                        *\*)
                            prefix=${pattern%\*}
                            if [ -z "$prefix" ] || [ "${elem#"$prefix"}" != "$elem" ]; then
                                covered=1
                            fi
                            ;;
                        *)
                            [ "$elem" = "$pattern" ] && covered=1
                            ;;
                    esac
                    j=$((j + 1))
                done
                if [ "$covered" != "1" ]; then
                    echo "ERROR: $name keychain-access-group '$elem' is not covered by its profile" >&2
                    return 1
                fi
                i=$((i + 1))
            done
        elif [ "$bin_val" != "$prof_val" ]; then
            echo "ERROR: $name entitlement '$key' is '$bin_val' but its profile grants '$prof_val'" >&2
            return 1
        fi
    done <<COVERAGE_KEYS
$(printf '%s' "$ent" | plist_dict_keys)
COVERAGE_KEYS
    echo "    ✓ $name entitlements are all granted by its embedded provisioning profile"
}

verify_profile_entitlement_coverage() {
    local bundle="$1" name="$2"
    local profile="$bundle/Contents/embedded.provisionprofile"
    local ent prof

    if [ ! -f "$profile" ] || [ -L "$profile" ]; then
        echo "ERROR: $name has no regular embedded.provisionprofile" >&2
        return 1
    fi
    if ! ent=$(/usr/bin/codesign -d --entitlements - --xml "$bundle" 2>/dev/null); then
        echo "ERROR: cannot read $name entitlements" >&2
        return 1
    fi
    if ! prof=$(/usr/bin/security cms -D -i "$profile" 2>/dev/null \
            | /usr/bin/plutil -extract Entitlements xml1 -o - -); then
        echo "ERROR: cannot decode $name provisioning-profile entitlements" >&2
        return 1
    fi
    verify_entitlement_coverage_plists "$ent" "$prof" "$name"
}

# The two entitlement-bearing components, checked wherever the bare tools are.
verify_entitled_component_coverage() {
    local app="$1" phase="$2"
    verify_profile_entitlement_coverage "$app" "$phase MacCrab.app" || return 1
    verify_profile_entitlement_coverage \
        "$app/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension" \
        "$phase com.maccrab.agent.systemextension" || return 1
}
# END BARE_TOOL_RELEASE_GUARDS

# Staging dir + EXIT-cleanup policy depend on the run mode.
#   all-stages: per-PID dir under /tmp, trap-cleaned on exit (historical).
#   single-stage: deterministic dir under .build so the next stage finds
#                 it; NOT trap-cleaned (the pipeline owns its lifetime —
#                 `unsigned-build` clears it, `publish` removes it at the
#                 end just like the all-stages flow did).
if [ "$STAGE" = "all" ]; then
    STAGING_DIR="/private/tmp/maccrab-release-$$"
    RELEASE_CLEAN_STAGING_ON_EXIT=1
    # Clean up the staging dir on any exit path. Without this handler, every
    # failed release run (Sparkle resolve failure, codesign failure,
    # hdiutil failure, notarize timeout) leaks a multi-MB staged dir to
    # /tmp; ten failed runs filled the dev disk before the audit caught
    # this. The handler fires after the final rm too, so successful runs
    # still pass through cleanly (the dir is already gone).
else
    STAGING_DIR="$PROJECT_DIR/.build/maccrab-stage"
fi
trap cleanup_release_build EXIT

cd "$PROJECT_DIR"

# State carried between stage processes. unsigned-build writes it; the
# later stages parse it as allowlisted data so VERSION / BUILD_NUMBER / SU_* stay pinned
# to the values the bundle was actually stamped with.
STAGE_ENV="$STAGING_DIR/.build-release-stage-env"

ENV_FILE="$HOME/.maccrab-release-env"

load_signing_phase_values() {
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
}

require_tracked_signing_inputs() {
    local input
    if [ "${MACCRAB_TRACKED_EXPORT:-0}" = "1" ]; then
        if [ -e "$PROJECT_DIR/.git" ] || [ -e "$PROJECT_DIR/.swiftpm" ]; then
            echo "ERROR: tracked-only build export contains forbidden Git/SwiftPM local state" >&2
            return 1
        fi
        if ! [[ "${MACCRAB_RELEASE_SOURCE_COMMIT:-}" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
                || ! [[ "${MACCRAB_RELEASE_SOURCE_TREE:-}" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
            echo "ERROR: tracked-only build lacks a valid source commit/tree attestation" >&2
            return 1
        fi
        for input in \
            Xcode/Resources/MacCrabApp.entitlements \
            Xcode/Resources/MacCrabAgent.entitlements; do
            if [ ! -f "$input" ] || [ -L "$input" ]; then
                echo "ERROR: tracked-only export lacks a regular signing input: $input" >&2
                return 1
            fi
        done
        return 0
    fi
    for input in \
        Xcode/Resources/MacCrabApp.entitlements \
        Xcode/Resources/MacCrabAgent.entitlements; do
        if ! $GIT_BIN ls-files --error-unmatch "$input" >/dev/null 2>&1; then
            echo "ERROR: release signing input is not tracked by Git: $input" >&2
            echo "       A public source tag must describe every shipped capability." >&2
            return 1
        fi
        if ! $GIT_BIN diff --quiet -- "$input" || ! $GIT_BIN diff --cached --quiet -- "$input"; then
            echo "ERROR: release signing input differs from HEAD: $input" >&2
            return 1
        fi
    done
}

# ─── Sparkle config: single source of truth ──────────────────────────
# The shipped app's Info.plist (heredoc below) used to HARDCODE SUPublicEDKey
# + SUFeedURL — a third independent copy that prerelease-check.sh never
# validated (it only compares project.yml vs MacCrabApp-Info.plist). A future
# key rotation that updated those two but forgot this script would pass the
# pre-release gate GREEN while shipping a DMG with a stale key, bricking
# auto-update for every installed user (a yank-class failure). Derive both
# from Xcode/project.yml (canonical) at build time and fail hard if absent, so
# there is exactly ONE source and no drift surface.
load_sparkle_config() {
    SU_EDKEY=$(grep -E '^[[:space:]]*SUPublicEDKey:' Xcode/project.yml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    SU_FEEDURL=$(grep -E '^[[:space:]]*SUFeedURL:' Xcode/project.yml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$SU_EDKEY" ] || [ -z "$SU_FEEDURL" ]; then
        echo "  ERROR: could not read SUPublicEDKey / SUFeedURL from Xcode/project.yml — refusing to build a DMG with missing Sparkle config" >&2
        exit 1
    fi
}

# ═════════════════════════════════════════════════════════════════════
# STAGE 1 — unsigned-build
#   Compile both architectures, lipo universal binaries, compile rules,
#   stamp the bundle-version marker + the rule-manifest hashes. Produces
#   $STAGING_DIR/bin + $STAGING_DIR/compiled_rules + rules_source. No
#   .app, no signing, no Apple round-trip. This stage is also useful for
#   local reproducibility checks; this repository has no hosted CI runner.
# ═════════════════════════════════════════════════════════════════════
stage_unsigned_build() {
    local toolchain_evidence_dir
    toolchain_evidence_dir=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/maccrab-release-toolchain.XXXXXX")
    echo "Toolchain qualification evidence: $toolchain_evidence_dir"
    /usr/bin/python3 -I "$SCRIPT_DIR/run-ci-phase.py" \
        --label "Release Swift toolchain identity" --timeout-seconds 30 \
        --log "$toolchain_evidence_dir/toolchain.log" --result "$toolchain_evidence_dir/toolchain.json" \
        -- /usr/bin/python3 -I "$SCRIPT_DIR/check-swift-toolchain.py"
    if [ "${MACCRAB_REQUIRE_TRACKED_RELEASE_INPUTS:-0}" = "1" ]; then
        require_tracked_signing_inputs
    fi
    load_sparkle_config
    echo "Building MacCrab v$VERSION..."
    echo "  CFBundleShortVersionString: $VERSION"
    echo "  CFBundleVersion           : $BUILD_NUMBER"
    echo "  Sparkle: feed=$SU_FEEDURL key=${SU_EDKEY:0:8}… (from project.yml)"

    # Fresh staging tree for this build. In single-stage mode this clears
    # any leftover from a prior run so the manifest/hashes can't go stale.
    rm -rf "$STAGING_DIR"
    mkdir -p "$STAGING_DIR/bin"

    # Persist the build identity so the assemble / sign / publish stages
    # stamp + sign the SAME version + build number this stage compiled.
    cat > "$STAGE_ENV" <<STAGE_ENV_EOF
VERSION="$VERSION"
BUILD_NUMBER="$BUILD_NUMBER"
SU_EDKEY="$SU_EDKEY"
SU_FEEDURL="$SU_FEEDURL"
CHANNEL="$CHANNEL"
SU_AUTOCHECK="$SU_AUTOCHECK"
STAGE_ENV_EOF
    chmod 0600 "$STAGE_ENV"

    # Copy a byte-for-byte allowlist of PyYAML into private staging before any
    # Python import. The source is never imported; the staged copy is re-hashed.
    "$SCRIPT_DIR/prepare-release-pyyaml.sh" "$STAGING_DIR/release-python" >/dev/null

    # ─── Compile for both architectures ──────────────────────────────
    # Each arch MUST build. Keep the full output in private staging so a failure
    # prints actionable compiler/resource diagnostics instead of the former
    # blank final line. Successful builds retain the concise final-line output.
    # Pre-fix, a failed x86_64 compile left arm64-only binaries that the lipo
    # loop below copied as "arm64 only" while stage_publish still labeled the
    # DMG "universal" — handing Intel users an un-runnable app with no gate.
    build_release_architecture() {
        local architecture="$1"
        local failure_message="$2"
        local build_log="$STAGING_DIR/build-$architecture.log"
        if $SWIFT_BIN build -c release --arch "$architecture" >"$build_log" 2>&1; then
            /usr/bin/tail -1 "$build_log"
            /bin/rm -f "$build_log"
            return 0
        fi
        echo "  ✗ ABORT: $failure_message" >&2
        echo "  Last 200 build-log lines:" >&2
        /usr/bin/tail -200 "$build_log" >&2
        return 1
    }

    echo "  Building arm64..."
    build_release_architecture arm64 \
        "arm64 release build failed — refusing to ship." || exit 1

    echo "  Building x86_64..."
    build_release_architecture x86_64 \
        "x86_64 release build failed — refusing to ship a single-arch build mislabeled \"universal\"." || exit 1

    # `swift build` resolved the exact Sparkle pin. Authenticate the checkout,
    # binary-artifact checksum and release helper hashes now, while this clean
    # resolution is the source for both the framework and later appcast tools.
    "$SCRIPT_DIR/check-release-dependencies.sh" >/dev/null

    # Create universal binaries for every product. maccrabd still builds
    # (it's the legacy SPM target used during `swift run` development) but
    # isn't shipped — the system extension replaces it in the installed .app.
    # maccrab-tierb-sandbox-host = the signed sandbox trampoline (enforces
    # third-party plugin containment); maccrab-tierb-example = the reference
    # collector shipped for contributors. Both are C executables.
    for binary in maccrabctl maccrab-mcp MacCrabApp MacCrabAgent maccrab-tierb-sandbox-host maccrab-tierb-example; do
        ARM_BIN="$PROJECT_DIR/.build/arm64-apple-macosx/release/$binary"
        X86_BIN="$PROJECT_DIR/.build/x86_64-apple-macosx/release/$binary"
        if [ -f "$ARM_BIN" ] && [ -f "$X86_BIN" ]; then
            lipo -create "$ARM_BIN" "$X86_BIN" -output "$STAGING_DIR/bin/$binary"
            echo "    ✓ $binary (universal)"
        elif [ -f "$ARM_BIN" ]; then
            cp "$ARM_BIN" "$STAGING_DIR/bin/$binary"
            echo "    ✓ $binary (arm64 only)"
        fi
        # Strip the Mach-O debug map (N_OSO/SO stabs) AND local symbols BEFORE
        # any signing. Unstripped release binaries embed absolute build paths
        # (/Users/<operator>/…/.build/…) and the four statically-linked Swift
        # executables otherwise duplicate roughly 70 MiB of non-runtime local
        # symbol data in the installed app. `-x` retains externally-visible /
        # dynamically-required symbols; the post-sign and mounted-DMG execution
        # probes below prove the final ctl/MCP products still launch. Must run
        # here (pre-codesign) because any later strip invalidates the signature.
        if [ -f "$STAGING_DIR/bin/$binary" ]; then
            if ! strip -S -x "$STAGING_DIR/bin/$binary"; then
                echo "ERROR: failed to strip release-only symbols from $binary" >&2
                exit 1
            fi
        fi
    done

    # ─── Rules ───────────────────────────────────────────────────────
    echo "  Compiling detection rules..."
    "$SCRIPT_DIR/run-release-python.sh" "$STAGING_DIR/release-python" \
        "$PROJECT_DIR/Compiler/compile_rules.py" \
        --input-dir "$PROJECT_DIR/Rules/" \
        --output-dir "$STAGING_DIR/compiled_rules" --compact-json 2>&1 | tail -1
    cp -r Rules/ "$STAGING_DIR/rules_source/"
    # v1.12.0: graph rules (Rules/graph/*.json) are already JSON — no
    # compilation step. Stage them next to the compiled single-event
    # rules so GraphRuleEvaluator can load them at daemon start. Pre-fix
    # the release DMG shipped without these and `maccrab_worm_self_propagation`
    # (the flagship Wave-1 detection) silently never fired in production.
    mkdir -p "$STAGING_DIR/compiled_rules/graph"
    cp Rules/graph/*.json "$STAGING_DIR/compiled_rules/graph/" 2>/dev/null || true
    # v1.4.2: also stamp a bundle version marker so RuleBundle on app
    # launch can compare against the installed rules and copy when newer.
    echo "$VERSION" > "$STAGING_DIR/compiled_rules/.bundle_version"

    # v1.4.3: tamper-detection manifest. For every compiled_rules file
    # we stamp a SHA-256 into manifest.json. BundledRuleSynchronizer verifies
    # both the sysext-sealed source and the installed tree before any reader
    # starts. Generated at build time so the manifest is signed into both the
    # app seed and the root-executing System Extension.
    echo "  Generating rule-manifest hashes..."
    (
        cd "$STAGING_DIR/compiled_rules"
        # Build a JSON object keyed by relative path with SHA-256 hex values.
        # Excludes the manifest itself and the .bundle_version marker.
        {
            echo '{'
            echo '  "schema_version": 1,'
            echo "  \"bundle_version\": \"$VERSION\","
            echo '  "hashes": {'
            find . -type f ! -name "manifest.json" ! -name ".bundle_version" \
                | sort \
                | while IFS= read -r f; do
                    rel="${f#./}"
                    sum=$($SHASUM_BIN -a 256 "$f" | /usr/bin/awk '{print $1}')
                    echo "    \"$rel\": \"$sum\","
                done \
                | sed '$ s/,$//'     # trim trailing comma on final entry
            echo '  }'
            echo '}'
        } > manifest.json
    )
    echo "  Manifest: $(wc -l < "$STAGING_DIR/compiled_rules/manifest.json") lines"
}

# ═════════════════════════════════════════════════════════════════════
# STAGE 2 — assemble
#   Hand-assemble MacCrab.app: app binary, 14 top-level *.lproj, bundled
#   rule compiler + PyYAML, UUID-named rule YAML, compiled rules, SPM
#   resource bundles (+ macOS-26 plist patch), bundled CLIs, the app
#   Info.plist heredoc, and the .systemextension bundle layout. No
#   signing. Reads $STAGING_DIR/bin from stage 1.
# ═════════════════════════════════════════════════════════════════════
stage_assemble() {
    # ─── App bundle skeleton ─────────────────────────────────────────
    echo "  Creating MacCrab.app bundle..."
    APP="$STAGING_DIR/MacCrab.app"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
    cp "$STAGING_DIR/bin/MacCrabApp" "$APP/Contents/MacOS/MacCrab"

    # v1.18 localization fix. SPM bundles the MacCrabApp target's .lproj into
    # Bundle.module (MacCrab_MacCrabApp.bundle), but all 396 String(localized:) call
    # sites resolve via Bundle.main — so without a top-level copy NONE of the 14
    # locales loaded at runtime (long-standing bug: the Settings language picker set
    # AppleLanguages + restarted, but Bundle.main had no .lproj to match → every key
    # fell back to its English defaultValue). Copy them to the app's top-level
    # Resources (the standard .app localization layout) so Bundle.main resolves them.
    # Also restores the correct region casing (zh-Hans, pt-BR) that SPM lowercases.
    lproj_count=0
    for lproj in Sources/MacCrabApp/Resources/*.lproj; do
        [ -d "$lproj" ] || continue
        cp -R "$lproj" "$APP/Contents/Resources/"
        lproj_count=$((lproj_count + 1))
    done
    # v1.18.1 guard: the glob silently matches zero dirs if the source layout
    # changes (e.g. a .strings → .xcstrings migration), which would ship an
    # all-English app — the exact bug 345f079 fixed. 14 is the shipped locale
    # count; bump it deliberately when adding a locale.
    if [ "$lproj_count" -ne 14 ]; then
        echo "ERROR: expected 14 .lproj localizations, found $lproj_count — aborting (Bundle.main localization would silently regress)" >&2
        exit 1
    fi
    # Bundle.main lookup is case-sensitive and SPM lowercases these two in
    # Bundle.module; the source-tree copy must preserve the correct casing.
    for cased in zh-Hans pt-BR; do
        if [ ! -d "$APP/Contents/Resources/${cased}.lproj" ]; then
            echo "ERROR: ${cased}.lproj missing or mis-cased in app Resources" >&2
            exit 1
        fi
    done
    echo "    ✓ Bundled $lproj_count localizations → Resources/*.lproj (Bundle.main)"

    # Keep redistribution notices with the installed app, including the
    # vendored SQLCipher and bundled PyYAML components. Copy before signing so
    # installed notices are bound to the same sealed bundle as their binaries.
    cp "$PROJECT_DIR/LICENSE" "$APP/Contents/Resources/"
    cp "$PROJECT_DIR/THIRD_PARTY_LICENSES.md" "$APP/Contents/Resources/"
    cp -R "$PROJECT_DIR/ThirdPartyNotices" "$APP/Contents/Resources/"

    # v1.12.0 RC16 (in-dashboard Sigma editor): bundle compile_rules.py
    # plus a hash-locked copy of PyYAML's pure-Python module so the dashboard
    # can compile user-edited YAML to the daemon-readable JSON format on
    # save. The copy was staged and verified before rule compilation; never
    # import or copy directly from the release user's site-packages here.
    mkdir -p "$APP/Contents/Resources/Compiler/yaml"
    cp Compiler/compile_rules.py "$APP/Contents/Resources/Compiler/compile_rules.py"
    "$SCRIPT_DIR/check-release-pyyaml.sh" "$STAGING_DIR/release-python" >/dev/null
    cp "$STAGING_DIR/release-python/yaml/"*.py "$APP/Contents/Resources/Compiler/yaml/"
    cp "$SCRIPT_DIR/release-dependencies.lock" "$APP/Contents/Resources/Compiler/"
    cp "$SCRIPT_DIR/release-pyyaml.sha256" "$APP/Contents/Resources/Compiler/"
    echo "    ✓ Bundled Compiler + hash-locked PyYAML ($(ls "$APP/Contents/Resources/Compiler/yaml/" | wc -l | tr -d ' ') yaml/ files) → Resources/Compiler/"

    # v1.12.0 fix (Edit-YAML): ship the rule YAML sources inside the .app
    # at Resources/rules/, named by the rule's Sigma `id:` UUID. The
    # dashboard's V2DetectionWorkspace passes `rule.id` (the YAML's `id:`
    # UUID like `d1a2b3c4-1003-4000-a000-000000001003`) to
    # `Bundle.main.path(forResource:ofType:"yml", inDirectory:"rules")`,
    # not the filename slug — so we need files named by UUID, not by slug.
    # We also copy the slug name for human browsing / debugging. Bundle
    # size cost: ~1 MB total for 463 rules; negligible vs the 80 MB DMG.
    mkdir -p "$APP/Contents/Resources/rules"
    # Pass 1: slug-named copies (filename-based browsing / debugging).
    find Rules -name '*.yml' -not -path 'Rules/graph/*' -exec cp {} "$APP/Contents/Resources/rules/" \;
    # Pass 2: UUID-named copies (Bundle.main.path lookup target).
    uuid_copied=0
    while IFS= read -r f; do
        uuid=$(grep -m1 '^id:' "$f" | awk '{print $2}' | tr -d "'\"" | tr -d '[:space:]')
        if [ -n "$uuid" ]; then
            cp "$f" "$APP/Contents/Resources/rules/$uuid.yml"
            uuid_copied=$((uuid_copied + 1))
        fi
    done < <(find Rules -name '*.yml' -not -path 'Rules/graph/*')
    echo "    ✓ Bundled $(ls "$APP/Contents/Resources/rules/" | wc -l | tr -d ' ') YAML files → Resources/rules/ ($uuid_copied UUID-named)"

    # Ship compiled rules inside the app as a signed parity/reference copy. The
    # same exact corpus is copied into the System Extension below; only the root
    # sysext publishes installed rules, after verifying its own code seal. This
    # keeps Sparkle updates fresh without a GUI-time privilege prompt or an
    # installer-time in-place corpus mutation.
    cp -r "$STAGING_DIR/compiled_rules" "$APP/Contents/Resources/compiled_rules"

    ICON_SRC="$PROJECT_DIR/Sources/MacCrabApp/Resources/AppIcon.icns"
    if [ -f "$ICON_SRC" ]; then
        cp "$ICON_SRC" "$APP/Contents/Resources/AppIcon.icns"
    fi

    # v1.12.0 RC2 fix (B9): copy SPM-generated MacCrab_MacCrabCore.bundle
    # into the .app's Resources directory. Without this, Bundle.module
    # returns nil at runtime in the shipped .app, and TyposquatDatabase
    # falls back to its in-source ~30-entry starter corpus instead of the
    # bundled top-200 npm + top-200 PyPI JSON files that
    # Sources/MacCrabCore/Resources/typosquat-top-*.json carry. SPM emits
    # the bundle into .build/<arch>/release/. We probe both Apple-silicon
    # (arm64) and Intel (x86_64) trees so universal builds get coverage.
    for arch in arm64-apple-macosx x86_64-apple-macosx; do
        SPM_BUNDLE="$PROJECT_DIR/.build/$arch/release/MacCrab_MacCrabCore.bundle"
        if [ -d "$SPM_BUNDLE" ]; then
            cp -R "$SPM_BUNDLE" "$APP/Contents/Resources/MacCrab_MacCrabCore.bundle"
            echo "    ✓ Bundled MacCrab_MacCrabCore resource bundle ($arch) → Resources/"
            break
        fi
    done
    # rc.4 — also copy the MacCrabApp resource bundle so bundled
    # rave kits + catalog signing key reach Bundle.main.resourceURL.
    for arch in arm64-apple-macosx x86_64-apple-macosx; do
        SPM_APP_BUNDLE="$PROJECT_DIR/.build/$arch/release/MacCrab_MacCrabApp.bundle"
        if [ -d "$SPM_APP_BUNDLE" ]; then
            cp -R "$SPM_APP_BUNDLE" "$APP/Contents/Resources/MacCrab_MacCrabApp.bundle"
            echo "    ✓ Bundled MacCrab_MacCrabApp resource bundle ($arch) → Resources/"
            break
        fi
    done
    # The rule channel is release-disabled pending an owner-approved offline key
    # rotation/custody record. Check the FINAL app tree that will be code-signed
    # and placed in the DMG; checking source alone would miss a stale resource.
    BUNDLED_RULES_PUB="$APP/Contents/Resources/MacCrab_MacCrabApp.bundle/rules.pub"
    if ! "$PROJECT_DIR/scripts/check-rules-trust-anchor.sh" --artifact-key "$BUNDLED_RULES_PUB"; then
        echo "    ✗ Disabled rule-channel invariant failed in final MacCrab.app" >&2
        exit 1
    fi
    echo "    ✓ Final MacCrab.app contains no rule-channel trust anchor"
    for required_bundle in MacCrab_MacCrabCore.bundle MacCrab_MacCrabApp.bundle; do
        if [ ! -d "$APP/Contents/Resources/$required_bundle" ] \
                || [ -L "$APP/Contents/Resources/$required_bundle" ]; then
            echo "    ✗ Required tracked resource bundle was not produced: $required_bundle" >&2
            echo "      Refusing to ship a fallback corpus or omit first-party app resources." >&2
            exit 1
        fi
    done
    for corpus_name in typosquat-top-npm.json typosquat-top-pypi.json; do
        source_corpus="$PROJECT_DIR/Sources/MacCrabCore/Resources/$corpus_name"
        bundled_corpus=$(/usr/bin/find \
            "$APP/Contents/Resources/MacCrab_MacCrabCore.bundle" \
            -type f -name "$corpus_name" -print)
        if [ ! -f "$source_corpus" ] || [ -L "$source_corpus" ] \
                || [ -z "$bundled_corpus" ] || [ ! -f "$bundled_corpus" ] \
                || [ -L "$bundled_corpus" ] \
                || [ "$($SHASUM_BIN -a 256 "$source_corpus" | /usr/bin/awk '{print $1}')" \
                    != "$($SHASUM_BIN -a 256 "$bundled_corpus" | /usr/bin/awk '{print $1}')" ]; then
            echo "    ✗ Bundled corpus does not exactly match tracked source: $corpus_name" >&2
            exit 1
        fi
    done
    echo "    ✓ Required resource bundles and tracked corpus bytes verified"

    # v1.12.4 fix (macOS 26 Tahoe crash): SwiftPM emits a stripped Info.plist
    # in the resource bundle that contains only CFBundleDevelopmentRegion.
    # macOS ≤ 25 accepts the minimal plist; macOS 26 rejects it — `Bundle(url:)`
    # returns nil — and SwiftPM's auto-generated `Bundle.module` accessor
    # then fatalError("unable to find bundle MacCrab_MacCrabCore"). Crash
    # fires on first Intelligence-tab click because PackageScanner lazily
    # instantiates TyposquatDatabase the first time .packages() is read.
    #
    # TyposquatDatabase itself no longer touches Bundle.module (it builds
    # resource URLs directly), but other future SPM-resource consumers
    # might — so write a complete CFBundle Info.plist over the SPM stub
    # so the bundle validates on every macOS version. Keys mirror what
    # Xcode emits for a typical resource bundle target.
    BUNDLE_PLIST="$APP/Contents/Resources/MacCrab_MacCrabCore.bundle/Info.plist"
    if [ -d "$APP/Contents/Resources/MacCrab_MacCrabCore.bundle" ]; then
        cat > "$BUNDLE_PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleIdentifier</key>
    <string>com.maccrab.MacCrabCore.resources</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>MacCrabCore Resources</string>
    <key>CFBundlePackageType</key>
    <string>BNDL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
</dict>
</plist>
PLIST
        echo "    ✓ Patched MacCrab_MacCrabCore.bundle/Info.plist (macOS 26 Bundle(url:) compatibility)"
    fi

    # Same macOS-26 Bundle(url:) patch for the MacCrabApp resource bundle — it
    # ships the same stripped SwiftPM Info.plist (only CFBundleDevelopmentRegion),
    # which pre-release-audit.sh Pass B flags as missing CFBundleIdentifier /
    # CFBundlePackageType / CFBundleInfoDictionaryVersion. Patch it too so the
    # whole app validates on macOS 26 regardless of which bundle a future
    # Bundle.module consumer touches.
    APP_BUNDLE_PLIST="$APP/Contents/Resources/MacCrab_MacCrabApp.bundle/Info.plist"
    if [ -d "$APP/Contents/Resources/MacCrab_MacCrabApp.bundle" ]; then
        cat > "$APP_BUNDLE_PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleIdentifier</key>
    <string>com.maccrab.MacCrabApp.resources</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>MacCrabApp Resources</string>
    <key>CFBundlePackageType</key>
    <string>BNDL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
</dict>
</plist>
PLIST
        echo "    ✓ Patched MacCrab_MacCrabApp.bundle/Info.plist (macOS 26 Bundle(url:) compatibility)"
    fi

    # v1.10.0: bundle maccrabctl + maccrab-mcp inside the .app at
    # Contents/Resources/bin/. Pre-fix the dashboard's runMaccrabctl
    # probed Bundle.main first, but the binary was only ever shipped to
    # /usr/local/bin via install.sh. Brew users with v1.5.1's CLI at
    # /opt/homebrew/bin/maccrabctl saw the dashboard call the OLD CLI
    # (no `intel refresh`, no `unsuppress --id`, etc.) — every dashboard
    # action that shells out failed silently with "Unknown command".
    # Now the .app carries the matching CLI and the path probe finds it
    # first.
    mkdir -p "$APP/Contents/Resources/bin"
    if [ -x "$STAGING_DIR/bin/maccrabctl" ]; then
        cp "$STAGING_DIR/bin/maccrabctl" "$APP/Contents/Resources/bin/maccrabctl"
        chmod 755 "$APP/Contents/Resources/bin/maccrabctl"
        echo "    ✓ Bundled maccrabctl into MacCrab.app/Contents/Resources/bin/"
    fi
    if [ -x "$STAGING_DIR/bin/maccrab-mcp" ]; then
        cp "$STAGING_DIR/bin/maccrab-mcp" "$APP/Contents/Resources/bin/maccrab-mcp"
        chmod 755 "$APP/Contents/Resources/bin/maccrab-mcp"
        echo "    ✓ Bundled maccrab-mcp into MacCrab.app/Contents/Resources/bin/"
    fi
    # The signed sandbox trampoline + the reference plugin. The trampoline is the
    # binary that enforces third-party plugin containment; SandboxedTierBRunner's
    # isRuntimeAvailable rejects it unless it is Developer-ID-signed (codesigned
    # below in the sign stage), so the third-party lane FAIL-CLOSES on any build
    # that doesn't ship it here. defaultTrampolinePath() finds it next to the CLI
    # (Resources/bin) and via ../Resources/bin from the app's Contents/MacOS.
    if [ -x "$STAGING_DIR/bin/maccrab-tierb-sandbox-host" ]; then
        cp "$STAGING_DIR/bin/maccrab-tierb-sandbox-host" "$APP/Contents/Resources/bin/maccrab-tierb-sandbox-host"
        chmod 755 "$APP/Contents/Resources/bin/maccrab-tierb-sandbox-host"
        echo "    ✓ Bundled the sandbox trampoline into MacCrab.app/Contents/Resources/bin/"
    else
        echo "    ⚠ maccrab-tierb-sandbox-host missing — the third-party plugin lane will fail-closed in this build."
    fi
    if [ -x "$STAGING_DIR/bin/maccrab-tierb-example" ]; then
        cp "$STAGING_DIR/bin/maccrab-tierb-example" "$APP/Contents/Resources/bin/maccrab-tierb-example"
        chmod 755 "$APP/Contents/Resources/bin/maccrab-tierb-example"
        echo "    ✓ Bundled the reference plugin into MacCrab.app/Contents/Resources/bin/"
    fi

    cat > "$APP/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>MacCrab</string>
    <key>CFBundleDisplayName</key><string>MacCrab</string>
    <key>CFBundleIdentifier</key><string>com.maccrab.app</string>
    <key>CFBundleVersion</key><string>${BUILD_NUMBER:-$VERSION}</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleExecutable</key><string>MacCrab</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIconName</key><string>AppIcon</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSSystemExtensionUsageDescription</key><string>MacCrab uses an Endpoint Security system extension to detect threats in real time. Approve once in System Settings &gt; General &gt; Login Items &amp; Extensions.</string>
    <key>NSMicrophoneUsageDescription</key><string>MacCrab monitors for ultrasonic voice injection attacks.</string>
    <key>NSFullDiskAccessUsageDescription</key><string>MacCrab needs Full Disk Access so the detection engine can read TCC state, observe access to protected paths, and detect tamper attempts against its own configuration.</string>
    <key>NSLocalNetworkUsageDescription</key><string>MacCrab inspects local network connections made by running processes to surface suspicious outbound patterns. Metadata stays on-device.</string>
    <key>NSHumanReadableCopyright</key><string>© 2026 CaddyLabs. MacCrab is distributed under the Apache 2.0 License.</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <!-- Sparkle 2 auto-update config. SUPublicEDKey is the ed25519
         verification key; losing the matching private key bricks
         updates for every existing install. Both values are interpolated
         from Xcode/project.yml (the single source of truth) — never edit
         them here; rotate the key in project.yml only. -->
    <key>SUFeedURL</key><string>${SU_FEEDURL}</string>
    <key>SUPublicEDKey</key><string>${SU_EDKEY}</string>
    <key>SUEnableAutomaticChecks</key><${SU_AUTOCHECK}/>
    <key>SUScheduledCheckInterval</key><integer>86400</integer>
    <key>SUAutomaticallyUpdate</key><false/>
    <!-- Build channel: "release" or "dev". Read this, never infer the
         channel from the version string. -->
    <key>MacCrabBuildChannel</key><string>${CHANNEL}</string>
    <!-- maccrab:// deep-link scheme (APPCORE-01). Routes `open maccrab://...`
         and in-app bookmarks to MacCrab.app via the scene .onOpenURL →
         V2DashboardState.goto(url:) pipeline. -->
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLName</key><string>com.maccrab.app.deeplink</string>
            <key>CFBundleURLSchemes</key>
            <array><string>maccrab</string></array>
        </dict>
    </array>
</dict>
</plist>
PLIST

    # ─── System extension bundle ─────────────────────────────────────
    AGENT_ID="com.maccrab.agent"
    SYSEXT_BUNDLE="$APP/Contents/Library/SystemExtensions/${AGENT_ID}.systemextension"
    mkdir -p "$SYSEXT_BUNDLE/Contents/MacOS" \
        "$SYSEXT_BUNDLE/Contents/Resources"

    # Mach-O executable name inside the sysext bundle. Convention: match
    # the bundle identifier so Apple's extension registration tooling
    # (systemextensionsctl, sysextd) locates it consistently.
    cp "$STAGING_DIR/bin/MacCrabAgent" "$SYSEXT_BUNDLE/Contents/MacOS/${AGENT_ID}"
    cp -R "$STAGING_DIR/compiled_rules" \
        "$SYSEXT_BUNDLE/Contents/Resources/compiled_rules"
    if ! /usr/bin/diff -qr \
            "$APP/Contents/Resources/compiled_rules" \
            "$SYSEXT_BUNDLE/Contents/Resources/compiled_rules" >/dev/null; then
        echo "ERROR: app and System Extension compiled-rule corpora drifted during assembly" >&2
        exit 1
    fi

    cat > "$SYSEXT_BUNDLE/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>MacCrabAgent</string>
    <key>CFBundleDisplayName</key><string>MacCrab Endpoint Security Extension</string>
    <key>CFBundleIdentifier</key><string>${AGENT_ID}</string>
    <key>CFBundleVersion</key><string>${BUILD_NUMBER:-$VERSION}</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleExecutable</key><string>${AGENT_ID}</string>
    <key>CFBundlePackageType</key><string>SYSX</string>
    <key>MacCrabBuildChannel</key><string>${CHANNEL}</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>NSSystemExtensionUsageDescription</key><string>MacCrab's endpoint security extension watches kernel events (process, file, network) to detect threats.</string>
    <!--
    Extension category. Without this key, systemextensionsctl rejects
    activation with "does not appear to belong to any extension
    categories". The Endpoint Security category specifically tells
    macOS to load this via sysextd with es_new_client eligibility.
    -->
    <key>NSSystemExtensionPointIdentifier</key><string>com.apple.system_extension.endpoint_security</string>
    <key>NSEndpointSecurityEarlyBoot</key><false/>
</dict>
</plist>
PLIST
    echo "    ✓ System extension bundle layout + sealed rule corpus created"

    # Strip any quarantine xattrs the filesystem picked up during staging.
    xattr -cr "$APP" 2>/dev/null || true
}

# ═════════════════════════════════════════════════════════════════════
# STAGE 3 — sign
#   codesign every Mach-O with Developer ID (CLIs, sysext Mach-O +
#   bundle with the ES entitlement, embedded Sparkle.framework + helpers,
#   rpath patch, bundled CLIs, app inner exe, and the outer .app — the
#   --deep-LESS outer sign that v1.12.2 settled on). Runs the
#   nested-entitlement leak guard. Ad-hoc signs when DEVELOPER_ID unset.
#   Requires the signing identity + provisioning profile on this Mac;
#   this stage never runs in CI.
# ═════════════════════════════════════════════════════════════════════
stage_sign() {
    APP="$STAGING_DIR/MacCrab.app"
    AGENT_ID="com.maccrab.agent"
    SYSEXT_BUNDLE="$APP/Contents/Library/SystemExtensions/${AGENT_ID}.systemextension"

    # ─── Code signing ────────────────────────────────────────────────
    # Provisioning profile + least-privilege entitlements per principal.
    # All live under version-controlled paths so the signing flow is
    # reproducible.
    DEVELOPER_ID="${DEVELOPER_ID:-}"
    APP_ENT="$PROJECT_DIR/Xcode/Resources/MacCrabApp.entitlements"
    AGENT_ENT="$PROJECT_DIR/Xcode/Resources/MacCrabAgent.entitlements"

    if [ -n "$DEVELOPER_ID" ]; then
        echo "  Signing with Developer ID..."
        if ! $SECURITY_BIN find-identity -v -p codesigning | /usr/bin/grep -q "$DEVELOPER_ID"; then
            echo "  ERROR: Certificate not found in keychain: $DEVELOPER_ID"
            exit 1
        fi

        PROVISION_PROFILE="${PROVISION_PROFILE:-$HOME/.maccrab-signing/MacCrab.provisionprofile}"
        if [ ! -f "$PROVISION_PROFILE" ]; then
            echo "  ERROR: Provisioning profile not found at $PROVISION_PROFILE"
            echo "  The ES system extension cannot be signed without it — v1.3.0 has no fallback path."
            exit 1
        fi
        echo "  Provisioning profile: $PROVISION_PROFILE"

        PROFILE_STAT_BEFORE=$(/usr/bin/stat -f 'size=%z;mtime=%m;mode=%Lp;uid=%u;gid=%g' "$PROVISION_PROFILE")
        PROFILE_SHA_BEFORE=$($SHASUM_BIN -a 256 "$PROVISION_PROFILE" | /usr/bin/awk '{print $1}')

        # Embed the profile at BOTH bundle levels. AMFI walks up from any
        # Mach-O to the nearest enclosing Contents/embedded.provisionprofile;
        # shipping it at both the sysext bundle and the app bundle covers
        # every discovery path Apple uses.
        cp "$PROVISION_PROFILE" "$APP/Contents/embedded.provisionprofile"
        cp "$PROVISION_PROFILE" "$SYSEXT_BUNDLE/Contents/embedded.provisionprofile"
        PROFILE_STAT_AFTER=$(/usr/bin/stat -f 'size=%z;mtime=%m;mode=%Lp;uid=%u;gid=%g' "$PROVISION_PROFILE")
        PROFILE_SHA_AFTER=$($SHASUM_BIN -a 256 "$PROVISION_PROFILE" | /usr/bin/awk '{print $1}')
        if [ "$PROFILE_STAT_BEFORE" != "$PROFILE_STAT_AFTER" ] \
                || [ "$PROFILE_SHA_BEFORE" != "$PROFILE_SHA_AFTER" ] \
                || [ "$($SHASUM_BIN -a 256 "$APP/Contents/embedded.provisionprofile" | /usr/bin/awk '{print $1}')" != "$PROFILE_SHA_BEFORE" ] \
                || [ "$($SHASUM_BIN -a 256 "$SYSEXT_BUNDLE/Contents/embedded.provisionprofile" | /usr/bin/awk '{print $1}')" != "$PROFILE_SHA_BEFORE" ]; then
            echo "  ERROR: provisioning profile changed during stable-copy attestation" >&2
            exit 1
        fi

        # Public, content-addressed evidence for every external build input.
        # No private key is opened. The profile is already a shipped public CMS
        # payload; only its digest is recorded publicly. Stable file metadata remains local.
        npm_corpus="$PROJECT_DIR/Sources/MacCrabCore/Resources/typosquat-top-npm.json"
        pypi_corpus="$PROJECT_DIR/Sources/MacCrabCore/Resources/typosquat-top-pypi.json"
        bundled_npm=$(/usr/bin/find "$APP/Contents/Resources/MacCrab_MacCrabCore.bundle" \
            -type f -name typosquat-top-npm.json -print)
        bundled_pypi=$(/usr/bin/find "$APP/Contents/Resources/MacCrab_MacCrabCore.bundle" \
            -type f -name typosquat-top-pypi.json -print)
        ATTESTATION_PATH="$APP/Contents/Resources/release-input-attestation.txt"
        XCODE_EVIDENCE=$($XCODEBUILD_BIN -version | /usr/bin/tr '\n' ';' | /usr/bin/sed 's/;*$//')
        SWIFT_EVIDENCE=$($SWIFT_BIN --version | /usr/bin/tr '\n' ';' | /usr/bin/sed 's/;*$//')
        if [ "${MACCRAB_TRACKED_EXPORT:-0}" = "1" ]; then
            BUILD_SOURCE_KIND=tracked-git-object-export
        else
            BUILD_SOURCE_KIND=standalone-live-worktree
        fi
        cat > "$ATTESTATION_PATH" <<ATTESTATION_EOF
format_version=1
build_source_kind=$BUILD_SOURCE_KIND
source_commit=${MACCRAB_RELEASE_SOURCE_COMMIT:-unbound}
source_tree=${MACCRAB_RELEASE_SOURCE_TREE:-unbound}
package_resolved_sha256=$($SHASUM_BIN -a 256 "$PROJECT_DIR/Package.resolved" | /usr/bin/awk '{print $1}')
release_dependency_lock_sha256=$($SHASUM_BIN -a 256 "$SCRIPT_DIR/release-dependencies.lock" | /usr/bin/awk '{print $1}')
pyyaml_manifest_sha256=$($SHASUM_BIN -a 256 "$SCRIPT_DIR/release-pyyaml.sha256" | /usr/bin/awk '{print $1}')
provisioning_profile_sha256=$PROFILE_SHA_BEFORE
core_npm_source_sha256=$($SHASUM_BIN -a 256 "$npm_corpus" | /usr/bin/awk '{print $1}')
core_npm_bundled_sha256=$($SHASUM_BIN -a 256 "$bundled_npm" | /usr/bin/awk '{print $1}')
core_pypi_source_sha256=$($SHASUM_BIN -a 256 "$pypi_corpus" | /usr/bin/awk '{print $1}')
core_pypi_bundled_sha256=$($SHASUM_BIN -a 256 "$bundled_pypi" | /usr/bin/awk '{print $1}')
xcode_toolchain=$XCODE_EVIDENCE
swift_toolchain=$SWIFT_EVIDENCE
ATTESTATION_EOF
        /bin/chmod 0444 "$ATTESTATION_PATH"
        echo "    ✓ Release input attestation embedded before code signing"

        # Remove raw MacCrabApp / MacCrabAgent from bin/ — the real copies
        # live inside the .app now. Leaving extra unsigned Mach-Os in the
        # DMG would cause notarization to reject the whole package.
        rm -f "$STAGING_DIR/bin/MacCrabApp"
        rm -f "$STAGING_DIR/bin/MacCrabAgent"

        # 1. Command-line products. Bare ctl/MCP executables have no eligible
        # provisioning-profile container, so they MUST remain entitlement-free;
        # otherwise AMFI kills them before main. They retain stable identifiers,
        # Developer ID, hardened runtime, and timestamp. Dashboard-stored cloud
        # keys are app-only; these tools use env overrides/local Ollama/fallbacks.
        for binary in "$STAGING_DIR"/bin/*; do
            if [ -f "$binary" ] && file "$binary" | grep -q "Mach-O"; then
                case "$(basename "$binary")" in
                    maccrabctl|maccrab-mcp)
                        sign_bare_tool "$binary" "$DEVELOPER_ID"
                        echo "    ✓ $(basename "$binary") (hardened runtime, no entitlements)"
                        ;;
                    *)
                        $CODESIGN_BIN --sign "$DEVELOPER_ID" \
                            --options runtime \
                            --timestamp \
                            --force \
                            "$binary"
                        echo "    ✓ $(basename "$binary") (hardened runtime)"
                        ;;
                esac
            fi
        done

        # 1b. The CLI tools + sandbox trampoline COPIED into the .app
        # (Contents/Resources/bin) need their OWN hardened-runtime signature —
        # the final app sign is intentionally NOT --deep (it only SEALS these via
        # CodeResources). SandboxedTierBRunner.isRuntimeAvailable refuses to run
        # any third-party plugin unless the trampoline is independently
        # Developer-ID-signed with our team, so without this the lane fail-closes.
        if [ -d "$APP/Contents/Resources/bin" ]; then
            for binary in "$APP"/Contents/Resources/bin/*; do
                if [ -f "$binary" ] && file "$binary" | grep -q "Mach-O"; then
                    case "$(basename "$binary")" in
                        maccrabctl|maccrab-mcp)
                            sign_bare_tool "$binary" "$DEVELOPER_ID"
                            echo "    ✓ .app/Resources/bin/$(basename "$binary") (hardened runtime, no entitlements)"
                            ;;
                        *)
                            $CODESIGN_BIN --sign "$DEVELOPER_ID" --options runtime --timestamp --force "$binary"
                            echo "    ✓ .app/Resources/bin/$(basename "$binary") (hardened runtime)"
                            ;;
                    esac
                fi
            done
        fi

        # 2. System extension Mach-O — signed with ES entitlement +
        # provisioning-profile-bound identifier. AMFI matches the identifier
        # against application-identifier in the embedded profile.
        $CODESIGN_BIN --sign "$DEVELOPER_ID" \
            --identifier "$AGENT_ID" \
            --options runtime \
            --entitlements "$AGENT_ENT" \
            --timestamp \
            --force \
            "$SYSEXT_BUNDLE/Contents/MacOS/${AGENT_ID}"

        # 3. System extension bundle — the bundle-level sign creates
        # _CodeSignature/CodeResources and seals the Info.plist + embedded
        # profile + Mach-O together.
        $CODESIGN_BIN --sign "$DEVELOPER_ID" \
            --identifier "$AGENT_ID" \
            --options runtime \
            --entitlements "$AGENT_ENT" \
            --timestamp \
            --force \
            "$SYSEXT_BUNDLE"
        echo "    ✓ Signed sysext bundle ($AGENT_ID, ES entitlement)"

        # 4a. Embed Sparkle.framework. SPM links MacCrabApp against Sparkle
        # (added in v1.3.5 Wave 1) but does NOT copy the framework into
        # the output bundle — that's an Xcode build-phase feature SPM
        # lacks. Without this step the dyld loader fails at launch with
        # "Library not loaded: @rpath/Sparkle.framework/Versions/B/Sparkle"
        # and the process aborts before SwiftUI gets a chance to render.
        # Dependency provenance was already authenticated by unsigned-build,
        # before signing credentials were loaded. Never execute dependency or
        # package tooling in the credential-bearing phase.
        SPARKLE_SRC="$PROJECT_DIR/.build/artifacts/sparkle/Sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework"
        if [ ! -d "$SPARKLE_SRC" ]; then
            echo "  ERROR: Sparkle.framework not found at $SPARKLE_SRC"
            echo "  Run the credential-free unsigned-build stage first; refusing to invoke SwiftPM while signing credentials are present."
            exit 1
        fi

        FRAMEWORKS_DIR="$APP/Contents/Frameworks"
        mkdir -p "$FRAMEWORKS_DIR"
        # -R preserves the framework's internal symlinks (Versions/B ↔ Current).
        # Without -R, macOS treats the copy as malformed and codesign rejects it.
        cp -R "$SPARKLE_SRC" "$FRAMEWORKS_DIR/"
        echo "    ✓ Embedded Sparkle.framework"

        # Re-sign Sparkle's bundled helpers + the framework itself with
        # our Developer ID. The framework arrives from the SPM artifact
        # already signed (by the Sparkle project's team); re-signing with
        # our identity keeps the whole app bundle's code-signing chain
        # consistent for notarization.
        for bundle in "$FRAMEWORKS_DIR/Sparkle.framework/Versions/B/XPCServices"/*.xpc \
                      "$FRAMEWORKS_DIR/Sparkle.framework/Versions/B/Autoupdate" \
                      "$FRAMEWORKS_DIR/Sparkle.framework/Versions/B/Updater.app"; do
            if [ -e "$bundle" ]; then
                $CODESIGN_BIN --sign "$DEVELOPER_ID" \
                    --options runtime \
                    --timestamp \
                    --force \
                    "$bundle" 2>/dev/null && echo "    ✓ Signed $(basename "$bundle")"
            fi
        done
        $CODESIGN_BIN --sign "$DEVELOPER_ID" \
            --options runtime \
            --timestamp \
            --force \
            "$FRAMEWORKS_DIR/Sparkle.framework"
        echo "    ✓ Signed Sparkle.framework"

        # SPM builds executables without `@executable_path/../Frameworks/`
        # in their rpath — that's Xcode's default for .app targets, which
        # SwiftPM doesn't know we're assembling. Without this, dyld
        # searches only `@executable_path/` (Contents/MacOS/) for
        # Sparkle.framework, misses our Contents/Frameworks/ copy, and
        # aborts at launch with "Library not loaded: @rpath/Sparkle.framework".
        # Add the rpath BEFORE signing so the code signature seals the
        # patched load commands.
        if ! otool -l "$APP/Contents/MacOS/MacCrab" | grep -q "@executable_path/../Frameworks"; then
            install_name_tool -add_rpath "@executable_path/../Frameworks" "$APP/Contents/MacOS/MacCrab"
            echo "    ✓ Added @executable_path/../Frameworks rpath"
        fi

        # 4b. App's inner executable. The app needs the
        # system-extension.install entitlement so OSSystemExtensionRequest
        # can talk to sysextd.
        $CODESIGN_BIN --sign "$DEVELOPER_ID" \
            --identifier "com.maccrab.app" \
            --options runtime \
            --entitlements "$APP_ENT" \
            --timestamp \
            --force \
            "$APP/Contents/MacOS/MacCrab"

        # 5. App bundle — signs the outer container last so the bundle
        # signature seals the sysext + the profile + the inner executable.
        #
        # Resources/* sealing (compiled_rules, rules, Compiler) is provided
        # by codesign's bundle-mode `_CodeSignature/CodeResources` hash
        # list — built automatically when signing the bundle, NO --deep
        # required. The original v1.12.0 RC28 audit fix added --deep on
        # the assumption that --deep was needed for Resources sealing;
        # that assumption was wrong — --deep is for recursing into nested
        # SIGNED code (frameworks, XPC services), not for sealing data
        # resources. CodeResources covers data resources unconditionally.
        #
        # v1.12.2 fix (Sparkle install FP): drop --deep. With --deep on,
        # codesign re-signed every nested Mach-O (Sparkle.framework's
        # Autoupdate, Updater.app, Downloader.xpc, Installer.xpc) and
        # propagated our main-app entitlements
        # (`com.apple.developer.system-extension.install` +
        # keychain-access-groups) onto each. macOS refuses to launch a
        # Sparkle XPC helper carrying the system-extension.install
        # entitlement, which surfaced as the generic "An error occurred
        # while running the updater" on every Sparkle upgrade. Tried
        # --preserve-metadata=entitlements first (v1.12.1) — turns out
        # codesign doesn't "preserve" the *absence* of entitlements, so
        # the propagation still happened. Dropping --deep is the actual
        # fix: Sparkle's helpers keep their step-4a signatures (no
        # entitlements), and the outer .app sign just seals the bundle
        # via its own primary executable (which already carries APP_ENT
        # from step 4b) plus the CodeResources hash list.
        $CODESIGN_BIN --sign "$DEVELOPER_ID" \
            --identifier "com.maccrab.app" \
            --options runtime \
            --entitlements "$APP_ENT" \
            --timestamp \
            --force \
            "$APP"
        echo "    ✓ Signed MacCrab.app (CodeResources seals Resources/, nested code kept own signatures)"

        # Verify before handing off to notarization — catches staging
        # layout mistakes fast. --deep emits many lines now that
        # Sparkle.framework is embedded (each helper + XPC service is
        # validated); head -5 closes the pipe early and triggers SIGPIPE
        # under `set -o pipefail`. Pipe through a shell function that
        # swallows SIGPIPE explicitly instead.
        CODESIGN_VERIFY_OUTPUT=$(/usr/bin/mktemp /private/tmp/maccrab-codesign-verify.XXXXXX)
        if ! $CODESIGN_BIN --verify --deep --strict --verbose=2 "$APP" \
                >"$CODESIGN_VERIFY_OUTPUT" 2>&1; then
            /usr/bin/head -20 "$CODESIGN_VERIFY_OUTPUT" >&2
            /bin/rm -f "$CODESIGN_VERIFY_OUTPUT"
            echo "  ERROR: blocking deep code-signature verification failed" >&2
            exit 1
        fi
        /usr/bin/head -5 "$CODESIGN_VERIFY_OUTPUT"
        /bin/rm -f "$CODESIGN_VERIFY_OUTPUT"

        # ── Nested-entitlement guard (v1.13 audit improvement; see the v1.12.0
        # Sparkle brick above). No nested helper may carry a privileged APP
        # entitlement: the v1.12.0 regression propagated system-extension.install
        # onto Sparkle's Installer.xpc and macOS refused to launch the updater.
        # Read-only; fails loud. Does NOT trip on a correct build (Sparkle XPCs
        # carry none; the sysext carries only endpoint-security.client).
        echo "  Verifying nested-binary entitlements (no privileged leak)..."
        ent_leak=0
        while IFS= read -r _xpc; do
            _exe=$(/usr/bin/find "$_xpc/Contents/MacOS" -maxdepth 1 -type f -print -quit 2>/dev/null)
            [ -n "$_exe" ] || continue
            if $CODESIGN_BIN -d --entitlements - "$_exe" 2>/dev/null | /usr/bin/grep -qiE 'system-extension\.install|endpoint-security'; then
                echo "    ✗ ENTITLEMENT LEAK: $(basename "$_xpc") carries a privileged app entitlement (v1.12.0-class regression)"
                ent_leak=1
            fi
        done < <(/usr/bin/find "$APP/Contents/Frameworks" -name '*.xpc' -type d 2>/dev/null)
        _sysexe="$APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
        if [ -f "$_sysexe" ] && $CODESIGN_BIN -d --entitlements - "$_sysexe" 2>/dev/null | /usr/bin/grep -qi 'system-extension\.install'; then
            echo "    ✗ ENTITLEMENT LEAK: system extension carries system-extension.install (app-only entitlement)"
            ent_leak=1
        fi
        if [ "$ent_leak" != "0" ]; then
            echo "  ERROR: nested-entitlement guard failed — refusing to ship (see the v1.12.0 Sparkle brick)."
            exit 1
        fi
        echo "    ✓ no privileged entitlement leaked to Sparkle XPC / sysext"

        # A bare executable with any restricted entitlement but no matching
        # per-tool provisioning profile is AMFI-killed before main. Prove every
        # slice of every loose/in-app copy has the stable identifier + hardened
        # runtime and ZERO entitlement keys. This catches both the rc.3 shared-
        # Keychain regression and an APP_ENT/AGENT_ENT copy-paste.
        echo "  Verifying bare CLI/MCP signature contract..."
        tool_entitlement_error=0
        for _tool in "$STAGING_DIR/bin/maccrabctl" \
                     "$STAGING_DIR/bin/maccrab-mcp" \
                     "$APP/Contents/Resources/bin/maccrabctl" \
                     "$APP/Contents/Resources/bin/maccrab-mcp"; do
            if ! verify_bare_tool_signature_contract "$_tool"; then
                tool_entitlement_error=1
            fi
        done
        if [ "$tool_entitlement_error" != "0" ]; then
            echo "  ERROR: bare CLI/MCP signature contract failed — refusing to ship."
            exit 1
        fi
        echo "    ✓ ctl/MCP have stable IDs + hardened runtime + zero entitlements"

        # Static signature validation does not ask taskgated/AMFI whether a
        # process may launch. Execute the final signed in-app binaries so a
        # provisioning-profile mismatch (exit 137 in rc.3–rc.5) blocks release.
        verify_bare_tool_runtime "$APP" "post-sign"
        verify_entitled_component_coverage "$APP" "post-sign"

        # Installed footprint is a product resource budget, not merely a DMG
        # compression statistic. A regression once left local symbols in four
        # universal Swift executables and grew MacCrab.app to ~207 MiB while the
        # compressed image looked comparatively small. Measure allocated bytes
        # after every nested component and signature is final.
        #
        # The real stripped baseline is ~154 MiB, NOT the ~136 MiB an earlier
        # comment here claimed: v1.21.6-rc.6, the first artifact this gate ever
        # measured, came in at 157,620 KiB. rc.12 was 159,508 KiB. rc.13's
        # authenticated event journal and terminal-evidence pipeline increased
        # the four statically linked universal Swift executables by 13.4 MiB in
        # aggregate; its final signed app measured 173,552 KiB after the local-
        # symbol and debug-map guards passed. The deliberate 180 MiB rebaseline
        # leaves 10,768 KiB of measured headroom while still catching a return
        # of the ~207 MiB unstripped regression. Print the margin on every build
        # so the number people act on is measured, not remembered — and so the
        # squeeze is visible long before the gate fires. It fires late and
        # expensively: after the universal build, lipo, strip, and every
        # signature.
        # v1.22.0: 184320 -> 185344 (180 -> 181 MiB), raised deliberately. The
        # inherited-FTS-desync boot fix needs roughly 52 KiB: MacCrabCore is
        # linked into the app, the sysext, maccrabctl and maccrab-mcp, so code
        # added there is paid for four times over. Trimmed twice first (the
        # degraded flag is internal, two log sites replace four) and it still
        # lands at 184344. The line has walked 183756 -> 184112 -> 184256 ->
        # 184292 across rc5..rc9, so one MiB is a few candidates of room, not a
        # reset of the ratchet. Shrink before raising this again.
        APP_FOOTPRINT_BUDGET_KIB=185344
        APP_FOOTPRINT_KIB=$(/usr/bin/du -sk "$APP" | /usr/bin/cut -f1)
        case "$APP_FOOTPRINT_KIB" in
            ''|*[!0-9]*)
                echo "ERROR: could not measure final MacCrab.app footprint" >&2
                exit 1
                ;;
        esac
        if [ "$APP_FOOTPRINT_KIB" -gt "$APP_FOOTPRINT_BUDGET_KIB" ]; then
            echo "ERROR: MacCrab.app footprint ${APP_FOOTPRINT_KIB} KiB exceeds the fixed ${APP_FOOTPRINT_BUDGET_KIB} KiB release budget" >&2
            echo "       Over by $((APP_FOOTPRINT_KIB - APP_FOOTPRINT_BUDGET_KIB)) KiB. Shrink the payload or raise the budget deliberately." >&2
            exit 1
        fi
        APP_FOOTPRINT_MARGIN_KIB=$((APP_FOOTPRINT_BUDGET_KIB - APP_FOOTPRINT_KIB))
        echo "    ✓ installed app footprint ${APP_FOOTPRINT_KIB} KiB (budget: ${APP_FOOTPRINT_BUDGET_KIB} KiB, margin: ${APP_FOOTPRINT_MARGIN_KIB} KiB / $((APP_FOOTPRINT_MARGIN_KIB * 100 / APP_FOOTPRINT_BUDGET_KIB))%)"

        # NOTE on stapling the .app bundle (intentionally NOT done): we validated
        # it and it does NOT work for this app. Even after a standalone app
        # notarization returns `status: Accepted`, `xcrun stapler staple
        # MacCrab.app` fails with Error 73 (no ticket) — a known finicky case for
        # apps that EMBED a System Extension. It's also unnecessary: `spctl -a -t
        # exec` already accepts the app as "Notarized Developer ID" (online
        # Gatekeeper, the real-world path), and the DMG below IS stapled for the
        # offline download/mount. So we sign + notarize (via the DMG) and skip the
        # per-build app-notarize round-trip that buys nothing here.
    else
        echo "  Ad-hoc signing (set DEVELOPER_ID for distribution signing)"
        $CODESIGN_BIN --force --sign - "$APP" 2>/dev/null || true
    fi
}

# ═════════════════════════════════════════════════════════════════════
# STAGE 4 — publish
#   Stage supporting files + install.sh, run the never-ship-private-keys
#   guard, build the DMG (attach + ditto + convert), sign + notarize the
#   DMG (via notarize.sh when creds are present). GA builds also write
#   release.json with rule/toolchain provenance and sed-bump both Homebrew
#   cask hashes; RC builds leave all production distribution metadata alone.
#   Removes the staging tree at the end.
# ═════════════════════════════════════════════════════════════════════
stage_publish() {
    APP="$STAGING_DIR/MacCrab.app"

    RELEASE_INPUT_ATTESTATION="$APP/Contents/Resources/release-input-attestation.txt"
    if [ "${MACCRAB_TRACKED_EXPORT:-0}" = "1" ]; then
        if [ ! -f "$RELEASE_INPUT_ATTESTATION" ] || [ -L "$RELEASE_INPUT_ATTESTATION" ] \
                || ! /usr/bin/grep -qx "build_source_kind=tracked-git-object-export" "$RELEASE_INPUT_ATTESTATION" \
                || ! /usr/bin/grep -qx "source_commit=${MACCRAB_RELEASE_SOURCE_COMMIT:-}" "$RELEASE_INPUT_ATTESTATION" \
                || ! /usr/bin/grep -qx "source_tree=${MACCRAB_RELEASE_SOURCE_TREE:-}" "$RELEASE_INPUT_ATTESTATION"; then
            echo "ERROR: signed app lacks the exact tracked-source input attestation" >&2
            exit 1
        fi
    fi
    if [ -f "$RELEASE_INPUT_ATTESTATION" ] && [ ! -L "$RELEASE_INPUT_ATTESTATION" ]; then
        RELEASE_INPUT_ATTESTATION_SHA=$($SHASUM_BIN -a 256 "$RELEASE_INPUT_ATTESTATION" | /usr/bin/awk '{print $1}')
    else
        RELEASE_INPUT_ATTESTATION_SHA=unavailable
    fi

    # ─── Supporting files + install.sh ───────────────────────────────
    cp "$PROJECT_DIR/LICENSE" "$STAGING_DIR/"
    cp "$PROJECT_DIR/README.md" "$STAGING_DIR/"
    cp "$PROJECT_DIR/THIRD_PARTY_LICENSES.md" "$STAGING_DIR/"
    cp -R "$PROJECT_DIR/ThirdPartyNotices" "$STAGING_DIR/"

    cp "$SCRIPT_DIR/install.sh" "$STAGING_DIR/install.sh"
    chmod +x "$STAGING_DIR/install.sh"

    # unsigned-build deliberately keeps bin/, compiled_rules/, rules_source/
    # and release-python/ as reproducible inputs to assembly/signing. They are
    # internal handoffs, not published payload, once the signed app contains
    # their runtime counterparts (the loose binaries alone added ~79 MiB to
    # rc.4). Validate every counterpart before pruning. The helper also
    # normalizes user-readable modes for install.sh and the app bundle.
    "$SCRIPT_DIR/prepare-dmg-payload.sh" "$STAGING_DIR"
    # Mode normalization happens after the signing stage, so repeat strict deep
    # verification against the exact app that will be copied into the image.
    # A green pre-normalization signature check is not release evidence.
    if ! $CODESIGN_BIN --verify --deep --strict "$APP"; then
        echo "ERROR: staged app signature failed after final payload normalization" >&2
        exit 1
    fi
    echo "    ✓ Staged app signature remains valid after payload normalization"

    # ─── Guard: never ship private-key material ──────────────────────
    # Regression guard for the security review's F7 ("dev/test keys ship")
    # concern. Scans the fully-assembled staging tree for PEM private-key
    # blocks. The marker "PRIVATE KEY" is unambiguous — it appears in real
    # private keys and nowhere legitimate in a shipped app (public keys say
    # "PUBLIC KEY"), so this cannot false-block a clean build. A match is a
    # stop-the-release event.
    if grep -rlI 'PRIVATE KEY' "$STAGING_DIR" >/dev/null 2>&1; then
        echo "  ✗ ABORT: private-key material found in the staging tree — refusing to package:"
        grep -rlI 'PRIVATE KEY' "$STAGING_DIR" | sed 's/^/      /'
        exit 1
    fi
    echo "    ✓ No private-key material in the staging tree"

    # Opsec: the internal build-staging dotfile must not ship in the DMG. It
    # carries only public values (version, build number, the PUBLIC Sparkle key,
    # feed URL) but is an internal artifact + leaks the build-number scheme to
    # users. Remove it from the payload before packaging. (It has already been
    # sourced by this stage, so removing it here is safe.)
    rm -f "$STAGE_ENV"

    # Opsec gate: no shipped Mach-O may leak the build machine's home path
    # (/Users/<operator>/… N_OSO debug-map stabs) in its symbol table. The
    # `strip -S` in the unsigned-build stage removes the debug map; this asserts
    # it actually worked for every shipped executable before we package + sign
    # the DMG. A match is a stop-the-release event.
    echo "  Verifying shipped binaries carry no build-path leakage..."
    LEAKED=""
    while IFS= read -r f; do
        if file -b "$f" 2>/dev/null | grep -q "Mach-O" && \
           nm -ap "$f" 2>/dev/null | grep -q "$HOME/"; then
            LEAKED="$LEAKED
      $f"
        fi
    done < <(find "$STAGING_DIR" -type f -perm -u+x)
    if [ -n "$LEAKED" ]; then
        echo "  ✗ ABORT: shipped binary leaks the build-machine home path ($HOME/…) in its symbol table:$LEAKED"
        echo "    (strip -S should have removed the debug map — investigate before release)"
        exit 1
    fi
    echo "    ✓ No build-path leakage in shipped binaries"

    # ─── Universal-binary gate ───────────────────────────────────────
    # Every Mach-O we ship MUST carry BOTH arm64 and x86_64. If an arch
    # build silently produced a single-arch binary (or a stale arm64-only
    # copy slipped through the unsigned-build lipo step), the DMG below is
    # still labeled "universal (arm64 + x86_64)" and Intel users get an
    # un-runnable app with no other gate to catch it. Assert each shipped
    # binary is 2-arch via `lipo -archs`; abort on any single-arch. Scope:
    # the app exe, the sysext exe, and the bundled CLIs / trampoline in
    # Resources/bin (the same paths the sign stage handled above).
    echo "  Verifying every shipped Mach-O is universal (arm64 + x86_64)..."
    UNIVERSAL_TARGETS=(
        "$APP/Contents/MacOS/MacCrab"
        "$APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
    )
    for _b in "$APP"/Contents/Resources/bin/*; do
        if [ -f "$_b" ]; then UNIVERSAL_TARGETS+=("$_b"); fi
    done
    for _b in "${UNIVERSAL_TARGETS[@]}"; do
        [ -f "$_b" ] || continue
        _archs=$(lipo -archs "$_b" 2>/dev/null || true)
        if ! echo "$_archs" | grep -qw arm64 || ! echo "$_archs" | grep -qw x86_64; then
            echo "  ✗ ABORT: $_b is not 2-arch (lipo -archs: '${_archs:-none}') — refusing to ship a single-arch build labeled \"universal\"." >&2
            exit 1
        fi
    done
    echo "    ✓ All shipped Mach-O binaries are universal (arm64 + x86_64)"

    # ─── DMG ─────────────────────────────────────────────────────────
    echo "  Creating DMG..."
    DMG_NAME="MacCrab-v$VERSION.dmg"
    DMG_PATH="$PROJECT_DIR/.build/$DMG_NAME"

    ln -s /Applications "$STAGING_DIR/Applications"

    # v1.18: build the DMG via attach + ditto + convert rather than
    # `hdiutil create -srcfolder`. The latter's internal copy fails with
    # "could not access .../MacCrab.app - Operation not permitted" once MacCrab is
    # INSTALLED on the build host (macOS App-Management protects the registered
    # com.maccrab.app from the diskimages-helper copy) — which is the normal
    # developer situation, and silently bricked the build the moment the dev dog-
    # fooded a prior RC. `ditto` into an explicitly-attached RW image is unaffected
    # and preserves the bundle + the /Applications symlink. The mountpoint is under
    # /tmp (not /Volumes) so a crash can't leave a stale /Volumes/MacCrab… volume.
    STAGE_KB=$(du -sk "$STAGING_DIR" | cut -f1)
    RW_DMG="${DMG_PATH%.dmg}.rw.dmg"
    /bin/rm -f "$RW_DMG"
    # The path becomes owned only after the stale exact-path work image is
    # removed.  From this assignment onward EXIT removes a partial image.
    RELEASE_RW_DMG_PATH="$RW_DMG"
    /usr/bin/hdiutil create -size "$(( STAGE_KB / 1024 + 150 ))m" -volname "MacCrab v$VERSION" \
        -fs HFS+ -ov "$RW_DMG" >/dev/null
    DMG_MNT=$(/usr/bin/mktemp -d /private/tmp/maccrab-dmg-mnt.XXXXXX)
    /bin/chmod 0700 "$DMG_MNT"
    RELEASE_DMG_MOUNT_PATH="$DMG_MNT"
    RELEASE_DMG_ATTACH_ATTEMPTED=1
    /usr/bin/hdiutil attach "$RW_DMG" -nobrowse -mountpoint "$DMG_MNT" >/dev/null
    /usr/bin/ditto "$STAGING_DIR/" "$DMG_MNT/"
    # Validate/normalize the actual mounted HFS payload too.  This catches a
    # transport-time mode regression rather than assuming staging modes survive
    # ditto.  The helper is idempotent after loose-payload pruning.
    if ! "$SCRIPT_DIR/prepare-dmg-payload.sh" "$DMG_MNT"; then
        echo "ERROR: mounted DMG payload validation/normalization failed" >&2
        exit 1
    fi
    # Verify the mounted HFS copy, not merely its source. This is the last app
    # pathname/content users receive before DMG conversion and catches mode or
    # metadata damage introduced by transport into the image.
    if ! $CODESIGN_BIN --verify --deep --strict "$DMG_MNT/MacCrab.app"; then
        echo "ERROR: mounted DMG app signature failed after final payload normalization" >&2
        exit 1
    fi
    echo "    ✓ Mounted DMG app passes strict deep signature verification"
    # Repeat against the transported HFS copy users receive. A staging-only
    # probe cannot detect copy/normalization/signature damage in the image.
    verify_bare_tool_runtime "$DMG_MNT/MacCrab.app" "mounted-DMG"
    verify_entitled_component_coverage "$DMG_MNT/MacCrab.app" "mounted-DMG"
    /usr/bin/hdiutil detach "$DMG_MNT" -force >/dev/null
    RELEASE_DMG_ATTACH_ATTEMPTED=0
    /bin/rmdir "$DMG_MNT"
    RELEASE_DMG_MOUNT_PATH=""
    /usr/bin/hdiutil convert "$RW_DMG" -format UDZO -ov -o "$DMG_PATH" >/dev/null
    /bin/rm -f "$RW_DMG"
    RELEASE_RW_DMG_PATH=""

    # Load signing/notary values only around the fixed notarization script.
    # They remain ordinary (unexported) shell variables here and are exported
    # solely to that one child command below.
    load_signing_phase_values
    if [ -n "${DEVELOPER_ID:-}" ] || [ -n "${APPLE_ID:-}" ]; then
        echo "  Signing and notarizing DMG..."
        DEVELOPER_ID="${DEVELOPER_ID:-}" \
        APPLE_ID="${APPLE_ID:-}" \
        APPLE_TEAM_ID="${APPLE_TEAM_ID:-}" \
        NOTARIZE_PASSWORD="${NOTARIZE_PASSWORD:-}" \
        NOTARIZE_KEYCHAIN_PROFILE="${NOTARIZE_KEYCHAIN_PROFILE:-}" \
            "$SCRIPT_DIR/notarize.sh" "$DMG_PATH"

        # audit #17: notarize.sh prints "Notarization skipped" and exits 0 when the
        # notary credential profile (NOTARIZE_KEYCHAIN_PROFILE)
        # are unset or expired — so a signed-but-UN-notarized DMG could sail through
        # to git push / gh release and hit Gatekeeper rejection on every download.
        # HARD-GATE it: the shipped DMG must be stapled AND spctl-accepted, unless
        # ALLOW_UNNOTARIZED=1 is explicitly set (the RC path — RCs are Developer-ID
        # signed but intentionally NOT notarized, installed via right-click→Open).
        if [ "${ALLOW_UNNOTARIZED:-0}" = "1" ]; then
            echo "  ⚠️  ALLOW_UNNOTARIZED=1 — skipping the notarization gate (RC / dev build)."
        else
            echo "  Verifying notarization (stapler + spctl)..."
            if ! $XCRUN_BIN stapler validate "$DMG_PATH" >/dev/null 2>&1; then
                echo "ERROR: $DMG_PATH is NOT stapled — notarization did not complete (credentials unset/expired?)." >&2
                echo "       Set the notary credentials and re-run, or ALLOW_UNNOTARIZED=1 for an intentional RC. Aborting." >&2
                exit 1
            fi
            if ! $SPCTL_BIN --assess -t open --context context:primary-signature "$DMG_PATH" >/dev/null 2>&1; then
                echo "ERROR: spctl rejected $DMG_PATH — Gatekeeper would block it on first launch. Aborting." >&2
                exit 1
            fi
            echo "  ✓ DMG is stapled and spctl-accepted."
        fi
    else
        echo "  Skipping code signing (set DEVELOPER_ID for Developer ID signing)"
    fi
    unset_maccrab_signing_env

    echo ""
    echo "═══════════════════════════════════════"
    echo "  MacCrab v$VERSION Release Built"
    echo "═══════════════════════════════════════"
    echo ""
    echo "  DMG: $DMG_PATH"
    echo "  Size: $(du -h "$DMG_PATH" | cut -f1)"
    echo "  Binaries: universal (arm64 + x86_64)"
    # v1.11.0 RC2 (audit ship MEDIUM): exclude `manifest.json` from the
    # rule count so release.json doesn't ship "428 rules" when the actual
    # count is 427. manifest.json is build-time metadata, not a rule.
    RULE_COUNT=$(find "$APP/Contents/Resources/compiled_rules" -name "*.json" ! -name "manifest.json" | wc -l | tr -d ' ')
    # v1.19.0 (S7-4): record the Sigma breakdown so release.json is the single
    # source of truth for the public 483 figure AND its composition. Counted
    # from the freshly-staged compiled tree so it can never drift from RULE_COUNT
    # (single-event + sequence + graph = total). `builtins` is the hardcoded
    # maccrab.* detection count (BuiltinRuleCatalog.all) — a separate, parallel
    # class, NOT part of the 483.
    RULES_SEQUENCE=$(find "$APP/Contents/Resources/compiled_rules/sequences" -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
    RULES_GRAPH=$(find "$APP/Contents/Resources/compiled_rules/graph" -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
    RULES_SINGLE=$(( RULE_COUNT - RULES_SEQUENCE - RULES_GRAPH ))
    BUILTINS=$(grep -c '\.init("maccrab\.' "$PROJECT_DIR/Sources/MacCrabCore/Detection/BuiltinRuleCatalog.swift" | tr -d ' ')
    echo "  Rules: $RULE_COUNT (single $RULES_SINGLE + sequence $RULES_SEQUENCE + graph $RULES_GRAPH) + $BUILTINS built-in"
    echo ""

    # v1.8.1: write release.json with version + rule + test counts so the
    # website can fetch authoritative metadata instead of being hand-edited.
    # Eliminates the version-drift class of bug that the v1.8.0 external
    # review caught (website still showed 1.7.12 / 929 tests).
    DMG_SHA=$($SHASUM_BIN -a 256 "$DMG_PATH" | /usr/bin/awk '{print $1}')
    if [[ "$VERSION" != *-rc.* ]]; then
        RELEASE_JSON="$PROJECT_DIR/release.json"
        DMG_SIZE_BYTES=$(stat -f%z "$DMG_PATH" 2>/dev/null || stat -c%s "$DMG_PATH")
    # `set -e` + grep returning 1 on no match would abort the script; route
    # through `|| true` so a missing test pattern doesn't kill the build.
    TEST_COUNT=$(find Tests -name '*.swift' -exec grep -h '^@Test\|^    @Test' {} + 2>/dev/null | wc -l | tr -d ' ' || true)
    SUITE_COUNT=$(find Tests -name '*.swift' -exec grep -h '^@Suite' {} + 2>/dev/null | wc -l | tr -d ' ' || true)
    TEST_COUNT="${TEST_COUNT:-0}"
    SUITE_COUNT="${SUITE_COUNT:-0}"
    RELEASE_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    # v1.18.1: record the toolchain for provenance — RELEASE_PROCESS.md notes
    # historical builds were unreproducible without this.
    TOOLCHAIN=$($XCODEBUILD_BIN -version 2>/dev/null | /usr/bin/tr '\n' ' ' | /usr/bin/sed 's/ *$//')
    TOOLCHAIN="${TOOLCHAIN:-unknown}"
        cat > "$RELEASE_JSON" <<RELEASE_EOF
{
  "version": "$VERSION",
  "release_date": "$RELEASE_DATE",
  "toolchain": "$TOOLCHAIN",
  "source_commit": "${MACCRAB_RELEASE_SOURCE_COMMIT:-unbound}",
  "source_tree": "${MACCRAB_RELEASE_SOURCE_TREE:-unbound}",
  "release_input_attestation_sha256": "$RELEASE_INPUT_ATTESTATION_SHA",
  "rules": $RULE_COUNT,
  "rules_single": $RULES_SINGLE,
  "rules_sequence": $RULES_SEQUENCE,
  "rules_graph": $RULES_GRAPH,
  "builtins": $BUILTINS,
  "tests": $TEST_COUNT,
  "test_suites": $SUITE_COUNT,
  "dmg": {
    "filename": "MacCrab-v${VERSION}.dmg",
    "url": "https://github.com/peterhanily/maccrab/releases/download/v${VERSION}/MacCrab-v${VERSION}.dmg",
    "sha256": "$DMG_SHA",
    "size_bytes": $DMG_SIZE_BYTES
  },
  "notes_url": "https://github.com/peterhanily/maccrab/releases/tag/v${VERSION}",
  "appcast_url": "https://maccrab.com/appcast.xml",
  "min_macos": "13.0"
}
RELEASE_EOF
        echo "  release.json written → $RELEASE_JSON"
    else
        echo "  RC build: production release.json remains on the current GA."
    fi

    # v1.18: bump the Homebrew cask sha256 to the freshly-built DMG. Pre-this it was
    # a manual step that lagged (a release shipped with the PRIOR version's cask
    # sha256, so `brew install --cask maccrab` failed checksum verification). The
    # DMG sha is authoritative here, so sync the cask(s) in the same breath.
    if [[ "$VERSION" == *-rc.* ]]; then
        echo "  RC build: production Homebrew casks remain on the current GA."
    else
        for cask in "$PROJECT_DIR/Casks/maccrab.rb" "$PROJECT_DIR/homebrew/maccrab.rb"; do
            [ -f "$cask" ] || continue
            /usr/bin/sed -i '' -E "s/sha256 \"[a-f0-9]{64}\"/sha256 \"$DMG_SHA\"/" "$cask"
        done
        echo "  Homebrew cask sha256 synced to the DMG ($DMG_SHA)"
    fi
    echo ""

    rm -rf "$STAGING_DIR"

    echo "Candidate bytes built only — do not tag, push, or publish this artifact directly."
    echo "Use scripts/release.sh's two-phase qualification flow; publication remains blocked on exact-candidate runtime and containment evidence."
}

# ─── Stage handoff helper ────────────────────────────────────────────
# Stages 2-4, when run individually, must reuse the VERSION / BUILD_NUMBER
# / Sparkle config the unsigned-build stage stamped — otherwise the
# Info.plist that `assemble` wrote and the bundle that `sign` seals would
# disagree (a re-derived per-second BUILD_NUMBER, or a Sparkle key that
# rotated between invocations). Parse the persisted env if present; the
# operator's explicit env vars still win for VERSION (so a single-stage
# re-run can target a different tag deliberately).
load_stage_env() {
    if [ -f "$STAGE_ENV" ]; then
        load_maccrab_env_file stage "$STAGE_ENV"
        export BUILD_NUMBER
        validate_build_number
    else
        echo "ERROR: stage '$STAGE' needs the staging tree from a prior 'unsigned-build' run," >&2
        echo "       but $STAGE_ENV was not found. Run:  scripts/build-release.sh unsigned-build" >&2
        exit 1
    fi
    # assemble re-stamps Info.plist from SU_* — ensure they're loaded even
    # if the env file predates this field set.
    if [ -z "${SU_EDKEY:-}" ] || [ -z "${SU_FEEDURL:-}" ]; then
        load_sparkle_config
    fi
    # Same guard for the build channel. A stage-env written before this
    # field existed would leave CHANNEL/SU_AUTOCHECK empty, and assemble
    # interpolates SU_AUTOCHECK directly into a plist element — an empty
    # value there yields malformed XML rather than a loud failure. Default
    # to the historical behaviour.
    if [ -z "${CHANNEL:-}" ]; then
        CHANNEL="release"
    fi
    if [ -z "${SU_AUTOCHECK:-}" ]; then
        if [ "$CHANNEL" = "dev" ]; then SU_AUTOCHECK="false"; else SU_AUTOCHECK="true"; fi
    fi
}

# ─── Dispatch ────────────────────────────────────────────────────────
case "$STAGE" in
    all)
        # Single-process, ordered pipeline — historical behavior. The
        # per-PID staging dir + EXIT trap (set above) own cleanup.
        stage_unsigned_build
        stage_assemble
        load_signing_phase_values
        stage_sign
        unset_maccrab_signing_env
        stage_publish
        ;;
    unsigned-build)
        stage_unsigned_build
        echo ""
        echo "  Stage 'unsigned-build' complete → $STAGING_DIR (bin/ + compiled_rules/)"
        echo "  Next: scripts/build-release.sh assemble"
        ;;
    assemble)
        load_stage_env
        stage_assemble
        echo ""
        echo "  Stage 'assemble' complete → $STAGING_DIR/MacCrab.app"
        echo "  Next: scripts/build-release.sh sign"
        ;;
    sign)
        load_stage_env
        load_signing_phase_values
        stage_sign
        unset_maccrab_signing_env
        echo ""
        echo "  Stage 'sign' complete."
        echo "  Next: scripts/build-release.sh publish"
        ;;
    publish)
        load_stage_env
        stage_publish
        ;;
esac
