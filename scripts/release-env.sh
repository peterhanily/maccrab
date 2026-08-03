#!/bin/bash
# Trusted shell library: import a data-only release/stage env after the Python
# reader has opened it no-follow, checked owner/mode/stability, and allowlisted
# every key. The untrusted env file itself is never sourced or evaluated.

load_maccrab_env_file() {
    local profile="${1:?profile required}"
    local path="${2:?path required}"
    local helper_dir helper parser_pid key value parser_status pipe_dir pipe_path
    helper_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    helper="$helper_dir/_release_env.py"

    if [[ ! -e "$path" && ! -L "$path" ]]; then
        return 0
    fi

    umask 077
    pipe_dir=$(/usr/bin/mktemp -d /private/tmp/maccrab-release-env.XXXXXX) || return 1
    pipe_path="$pipe_dir/parsed.pipe"
    if ! /usr/bin/mkfifo -m 600 "$pipe_path"; then
        /bin/rmdir "$pipe_dir" 2>/dev/null || true
        return 1
    fi
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
        /usr/bin/python3 -I "$helper" --profile "$profile" "$path" >"$pipe_path" &
    parser_pid=$!
    exec 9<"$pipe_path"
    /bin/rm -f "$pipe_path"
    while IFS= read -r -d '' key <&9; do
        if ! IFS= read -r -d '' value <&9; then
            exec 9<&-
            wait "$parser_pid" 2>/dev/null || true
            /bin/rmdir "$pipe_dir" 2>/dev/null || true
            echo "ERROR: truncated parsed env output" >&2
            return 1
        fi
        case "$profile:$key" in
            release:DEVELOPER_ID|release:APPLE_ID|release:APPLE_TEAM_ID|release:NOTARIZE_PASSWORD|release:NOTARIZE_KEYCHAIN_PROFILE|release:SITE_REPO_TOKEN|release:TAP_REPO_TOKEN|release:GH_TOKEN|signing:DEVELOPER_ID|signing:APPLE_ID|signing:APPLE_TEAM_ID|signing:NOTARIZE_PASSWORD|signing:NOTARIZE_KEYCHAIN_PROFILE|publisher:SITE_REPO_TOKEN|publisher:TAP_REPO_TOKEN|publisher:GH_TOKEN|stage:VERSION|stage:BUILD_NUMBER|stage:SU_EDKEY|stage:SU_FEEDURL|stage:CHANNEL|stage:SU_AUTOCHECK)
                printf -v "$key" '%s' "$value"
                ;;
            *)
                exec 9<&-
                wait "$parser_pid" 2>/dev/null || true
                /bin/rmdir "$pipe_dir" 2>/dev/null || true
                echo "ERROR: parser returned an unexpected env key: $key" >&2
                return 1
                ;;
        esac
    done
    exec 9<&-
    if wait "$parser_pid"; then parser_status=0; else parser_status=$?; fi
    /bin/rmdir "$pipe_dir" 2>/dev/null || true
    [[ "$parser_status" == "0" ]] || return "$parser_status"
}

# Remove credential names from both the shell and its exported environment.
# Callers copy any values they need into deliberately unexported phase-local
# variables before invoking this helper.
unset_maccrab_signing_env() {
    unset DEVELOPER_ID APPLE_ID APPLE_TEAM_ID NOTARIZE_PASSWORD \
        NOTARIZE_KEYCHAIN_PROFILE
}

unset_maccrab_publisher_env() {
    unset GH_TOKEN GITHUB_TOKEN SITE_REPO_TOKEN TAP_REPO_TOKEN
}
