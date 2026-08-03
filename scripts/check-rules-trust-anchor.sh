#!/bin/bash
# Deterministic release guard for the DISABLED rule-update channel. Until the
# owner records an offline key ceremony/custody decision, source and final app
# bundles must carry no rules.pub, the production policy literal must remain
# false, and the daemon must contain no pushed-corpus load call. This script
# never accepts, names, or searches for a private key.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SOURCE_KEY="$REPO_ROOT/Sources/MacCrabApp/Resources/rave-keys/rules.pub"
POLICY_SOURCE="$REPO_ROOT/Sources/MacCrabCore/Detection/RuleChannelPolicy.swift"
SOURCE_TREE="$REPO_ROOT/Sources"
ARTIFACT_KEY=""

usage() {
    echo "usage: $0 [--artifact-key path] [--source-key path] [--policy-source path] [--source-tree path]" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --artifact-key|--source-key|--policy-source|--source-tree)
            [ "$#" -ge 2 ] || usage
            case "$1" in
                --artifact-key) ARTIFACT_KEY="$2" ;;
                --source-key) SOURCE_KEY="$2" ;;
                --policy-source) POLICY_SOURCE="$2" ;;
                --source-tree) SOURCE_TREE="$2" ;;
            esac
            shift 2
            ;;
        *) usage ;;
    esac
done

if [ -e "$SOURCE_KEY" ] || [ -L "$SOURCE_KEY" ]; then
    echo "ERROR: disabled rule channel must not ship a source rules.pub: $SOURCE_KEY" >&2
    exit 1
fi

if [ -n "$ARTIFACT_KEY" ] && { [ -e "$ARTIFACT_KEY" ] || [ -L "$ARTIFACT_KEY" ]; }; then
    echo "ERROR: disabled rule channel must not ship rules.pub in the final app: $ARTIFACT_KEY" >&2
    exit 1
fi

if [ ! -f "$POLICY_SOURCE" ]; then
    echo "ERROR: rule-channel policy source is missing: $POLICY_SOURCE" >&2
    exit 1
fi
POLICY_DECLARATIONS="$(grep -Ec '^[[:space:]]*public static let productionEnabled[[:space:]]*=' "$POLICY_SOURCE" || true)"
POLICY_DISABLED="$(grep -Ec '^[[:space:]]*public static let productionEnabled[[:space:]]*=[[:space:]]*false[[:space:]]*$' "$POLICY_SOURCE" || true)"
if [ "$POLICY_DECLARATIONS" != "1" ] || [ "$POLICY_DISABLED" != "1" ]; then
    echo "ERROR: expected exactly one literal 'public static let productionEnabled = false' in $POLICY_SOURCE" >&2
    exit 1
fi

if [ ! -d "$SOURCE_TREE" ]; then
    echo "ERROR: source tree is missing: $SOURCE_TREE" >&2
    exit 1
fi
LOADER_REFERENCES="$(grep -R -n -E --include='*.swift' 'loadPushedRules[[:space:]]*\(' "$SOURCE_TREE" || true)"
LOADER_REFERENCE_COUNT="$(printf '%s\n' "$LOADER_REFERENCES" | awk 'NF { count++ } END { print count + 0 }')"
LOADER_DECLARATIONS="$(grep -R -n -E --include='*.swift' '^[[:space:]]*func[[:space:]]+loadPushedRules[[:space:]]*\(' "$SOURCE_TREE" || true)"
LOADER_DECLARATION_COUNT="$(printf '%s\n' "$LOADER_DECLARATIONS" | awk 'NF { count++ } END { print count + 0 }')"
if [ "$LOADER_REFERENCE_COUNT" != "1" ] || [ "$LOADER_DECLARATION_COUNT" != "1" ]; then
    echo "ERROR: disabled channel permits exactly one dormant, internal loadPushedRules declaration and no call sites" >&2
    [ -z "$LOADER_REFERENCES" ] || echo "$LOADER_REFERENCES" | sed 's/^/  /' >&2
    exit 1
fi

echo "rule channel disabled: policy=false, no source/final anchor, no pushed-corpus call sites"
