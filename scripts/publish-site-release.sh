#!/bin/bash
# Disable tracing before any credential or private build-input expansion.
set +x
# publish-site-release.sh — Publish appcast.xml and release.json to the site
# repo in ONE commit through the Git Data API.
#
# The site is a Cloudflare Worker serving the repo's files, and Workers Builds
# deploys every commit separately, not necessarily in commit order. The two
# files used to go out as two Contents API commits seconds apart. On 2026-09-22
# the older appcast commit's build started 17 s after the newer release.json
# commit's build and deployed last, so maccrab.com/release.json served 1.22.0
# for six days while every publish step reported success. One commit means one
# deploy carries both files; there is no older sibling left to land on top.
#
# The ref update is never forced. If anything moved the branch after this
# script read it, GitHub rejects the non-fast-forward update and nothing is
# published, instead of the other change being silently discarded.
#
# Usage:
#   SITE_REPO_TOKEN=... scripts/publish-site-release.sh \
#       --release-json FILE --site-repo OWNER/REPO --version X \
#       (--item FILE | --skip-appcast) [--branch NAME]
#
# --skip-appcast publishes release.json alone (release.sh passes it for
# SKIP_APPCAST=1 and when appcast generation failed). publish-appcast-entry.sh
# and publish-release-json.sh remain for single-file manual recovery.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CURL_BIN=/usr/bin/curl
ITEM=""
SKIP_APPCAST_ITEM=0
RELEASE_JSON=""
SITE_REPO="${SITE_REPO:-}"
VERSION=""
BRANCH="main"

usage() {
    echo "usage: $0 --release-json FILE --site-repo OWNER/REPO --version X (--item FILE | --skip-appcast) [--branch NAME]" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --item) [[ $# -ge 2 ]] || { usage; exit 2; }; ITEM="$2"; shift 2 ;;
        --skip-appcast) SKIP_APPCAST_ITEM=1; shift ;;
        --release-json) [[ $# -ge 2 ]] || { usage; exit 2; }; RELEASE_JSON="$2"; shift 2 ;;
        --site-repo) [[ $# -ge 2 ]] || { usage; exit 2; }; SITE_REPO="$2"; shift 2 ;;
        --version) [[ $# -ge 2 ]] || { usage; exit 2; }; VERSION="$2"; shift 2 ;;
        --branch) [[ $# -ge 2 ]] || { usage; exit 2; }; BRANCH="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
    esac
done

# Omitting --item must be a decision, not an accident: a release that silently
# published release.json alone would leave Sparkle users on the old build.
if [[ "$SKIP_APPCAST_ITEM" == 1 ]]; then
    [[ -z "$ITEM" ]] || { echo "ERROR: --item and --skip-appcast are mutually exclusive" >&2; exit 2; }
else
    [[ -n "$ITEM" && -f "$ITEM" && ! -L "$ITEM" ]] || {
        echo "ERROR: --item must be a regular no-link file (or pass --skip-appcast)" >&2; exit 2;
    }
fi
[[ -n "$RELEASE_JSON" && -f "$RELEASE_JSON" && ! -L "$RELEASE_JSON" ]] || {
    echo "ERROR: --release-json must be a regular no-link file" >&2; exit 2;
}
[[ -n "$SITE_REPO" && "$SITE_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "ERROR: unsafe --site-repo" >&2; exit 2; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || { echo "ERROR: unsafe or missing --version" >&2; exit 2; }
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ && "$BRANCH" != /* && "$BRANCH" != *..* && "$BRANCH" != *//* ]] || {
    echo "ERROR: unsafe --branch" >&2; exit 2;
}
[[ "${SITE_REPO_TOKEN:-}" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ERROR: SITE_REPO_TOKEN missing or malformed" >&2; exit 2; }

run_xml_helper() {
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C LANG=C \
        /usr/bin/python3 -I "$SCRIPT_DIR/_appcast_xml.py" "$@"
}

SITE_JSON_HELPER=$(/bin/cat <<'PY'
import base64, hashlib, json, os, re, sys

SHA = re.compile(r"[a-f0-9]{40}\Z")
LIMIT = 6 * 1024 * 1024


def fail(message):
    raise SystemExit("ERROR: " + message)


def read(path, limit=LIMIT):
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        fail(f"{os.path.basename(path)} exceeds {limit} bytes")
    return data


def load(path):
    try:
        return json.loads(read(path))
    except ValueError as exc:
        fail(f"GitHub returned non-JSON: {exc}")


def write(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, separators=(",", ":"))


def message(response):
    text = response.get("message") if isinstance(response, dict) else None
    return re.sub(r"[^ -~]", "?", text)[:200] if isinstance(text, str) else "no message"


command, args = sys.argv[1], sys.argv[2:]
if command == "check-release-json":
    path, version = args
    try:
        document = json.loads(read(path, 1024 * 1024))
    except ValueError as exc:
        fail(f"release.json is not JSON: {exc}")
    if not isinstance(document, dict) or document.get("version") != version:
        fail(f"release.json does not describe v{version}")
elif command == "sha":
    # sha RESPONSE DOTTED.PATH [EXPECTED]: print a validated object id.
    response = load(args[0])
    value = response
    for part in args[1].split("."):
        if isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        elif isinstance(value, dict):
            value = value.get(part)
        else:
            value = None
    if not isinstance(value, str) or not SHA.fullmatch(value):
        fail(f"GitHub response has no valid {args[1]} ({message(response)})")
    if len(args) > 2 and value != args[2]:
        fail(f"GitHub response {args[1]} is {value}, expected {args[2]}")
    print(value)
elif command == "single-parent":
    response = load(args[0])
    parents = response.get("parents") if isinstance(response, dict) else None
    if not isinstance(parents, list) or len(parents) != 1:
        fail("new commit does not have exactly one parent")
elif command == "blob-payload":
    # Print the Git object id GitHub must return, so a blob that does not
    # hold exactly these bytes is caught before it reaches a tree.
    data = read(args[0], 4 * 1024 * 1024)
    write(args[1], {"content": base64.b64encode(data).decode("ascii"), "encoding": "base64"})
    print(hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest())
elif command == "tree-payload":
    base_tree, output, entries = args[0], args[1], args[2:]
    write(output, {"base_tree": base_tree, "tree": [
        {"path": path, "mode": "100644", "type": "blob", "sha": sha}
        for path, sha in (entry.split("=", 1) for entry in entries)
    ]})
elif command == "commit-payload":
    text, tree, parent, output = args
    write(output, {"message": text, "tree": tree, "parents": [parent]})
elif command == "ref-payload":
    write(args[1], {"sha": args[0], "force": False})
elif command == "message":
    try:
        print(message(load(args[0])))
    except (OSError, SystemExit):
        print("unreadable response")
else:
    fail(f"unknown helper command {command}")
PY
)

site_json() {
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -c "$SITE_JSON_HELPER" "$@"
}

# Every local input is validated before the credential is written or any
# request is made: a malformed item or a release.json for another version
# cannot reach even a GET.
BUILD_ID=""
if [[ "$SKIP_APPCAST_ITEM" != 1 ]]; then
    BUILD_ID=$(run_xml_helper validate-item --item "$ITEM" --expected-version "$VERSION")
fi
site_json check-release-json "$RELEASE_JSON" "$VERSION"

WORK_DIR=$(/usr/bin/mktemp -d /private/tmp/maccrab-site-publish.XXXXXX)
trap '/bin/rm -rf "$WORK_DIR"' EXIT HUP INT TERM
AUTH_CONFIG="$WORK_DIR/curl-auth"

# Keep the PAT out of argv/process listings. The private config exists only in
# this mode-0700 temporary directory and is removed by the trap.
printf 'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n' \
    "$SITE_REPO_TOKEN" > "$AUTH_CONFIG"

publisher_curl() {
    $CURL_BIN -q --proto '=https' --noproxy '*' \
        --connect-timeout 10 --max-time 30 --config "$AUTH_CONFIG" "$@"
}

API="https://api.github.com/repos/${SITE_REPO}"

github_get() {
    publisher_curl -fsS --max-filesize 6291456 "$API/$1" --output "$2"
}

github_post() {
    publisher_curl -fsS --max-filesize 6291456 -X POST \
        -H "Content-Type: application/json" --data-binary "@$2" "$API/$1" --output "$3"
}

echo "Reading ${SITE_REPO} ${BRANCH}..."
github_get "git/ref/heads/${BRANCH}" "$WORK_DIR/ref.json"
BASE_COMMIT=$(site_json sha "$WORK_DIR/ref.json" object.sha)
github_get "git/commits/${BASE_COMMIT}" "$WORK_DIR/base-commit.json"
BASE_TREE=$(site_json sha "$WORK_DIR/base-commit.json" tree.sha)

TREE_ENTRIES=()
if [[ "$SKIP_APPCAST_ITEM" != 1 ]]; then
    # Read the feed at the exact commit the new one will descend from, not at
    # the branch name, so the merge and the parent cannot disagree.
    github_get "contents/appcast.xml?ref=${BASE_COMMIT}" "$WORK_DIR/appcast-response.json"
    run_xml_helper decode-github-response \
        --response "$WORK_DIR/appcast-response.json" --output "$WORK_DIR/current.xml" >/dev/null
    # Same merge as publish-appcast-entry.sh: rejects duplicate or
    # non-increasing Sparkle builds and parses the full result before writing.
    run_xml_helper inject \
        --item "$ITEM" \
        --current "$WORK_DIR/current.xml" \
        --output "$WORK_DIR/appcast.xml" \
        --expected-version "$VERSION" \
        --expected-build "$BUILD_ID"
    appcast_blob=$(site_json blob-payload "$WORK_DIR/appcast.xml" "$WORK_DIR/appcast-blob.json")
    github_post git/blobs "$WORK_DIR/appcast-blob.json" "$WORK_DIR/appcast-blob-response.json"
    site_json sha "$WORK_DIR/appcast-blob-response.json" sha "$appcast_blob" >/dev/null
    TREE_ENTRIES+=("appcast.xml=$appcast_blob")
    MSG="Publish v${VERSION}: appcast entry (build ${BUILD_ID}) and release.json"
else
    MSG="release.json: bump to v${VERSION}"
fi

release_blob=$(site_json blob-payload "$RELEASE_JSON" "$WORK_DIR/release-blob.json")
github_post git/blobs "$WORK_DIR/release-blob.json" "$WORK_DIR/release-blob-response.json"
site_json sha "$WORK_DIR/release-blob-response.json" sha "$release_blob" >/dev/null
TREE_ENTRIES+=("release.json=$release_blob")

site_json tree-payload "$BASE_TREE" "$WORK_DIR/tree.json" "${TREE_ENTRIES[@]}"
github_post git/trees "$WORK_DIR/tree.json" "$WORK_DIR/tree-response.json"
NEW_TREE=$(site_json sha "$WORK_DIR/tree-response.json" sha)

site_json commit-payload "$MSG" "$NEW_TREE" "$BASE_COMMIT" "$WORK_DIR/commit.json"
github_post git/commits "$WORK_DIR/commit.json" "$WORK_DIR/commit-response.json"
NEW_COMMIT=$(site_json sha "$WORK_DIR/commit-response.json" sha)
site_json sha "$WORK_DIR/commit-response.json" tree.sha "$NEW_TREE" >/dev/null
site_json sha "$WORK_DIR/commit-response.json" parents.0.sha "$BASE_COMMIT" >/dev/null
site_json single-parent "$WORK_DIR/commit-response.json"

echo "Moving ${SITE_REPO} ${BRANCH} ${BASE_COMMIT:0:12} -> ${NEW_COMMIT:0:12} (fast-forward only)..."
site_json ref-payload "$NEW_COMMIT" "$WORK_DIR/ref-update.json"
# No -f here: a refusal carries the reason in its body, and the operator needs
# it to tell a moved branch from a credential problem.
ref_status=$(publisher_curl -sS --max-filesize 1048576 -X PATCH \
        -H "Content-Type: application/json" --data-binary "@$WORK_DIR/ref-update.json" \
        --output "$WORK_DIR/ref-update-response.json" -w '%{http_code}' \
        "$API/git/refs/heads/${BRANCH}") || {
    echo "ERROR: the ${BRANCH} update request did not complete; its outcome is unknown." >&2
    echo "       Check whether ${SITE_REPO} ${BRANCH} points at ${NEW_COMMIT} before re-running." >&2
    exit 1
}
if [[ "$ref_status" != 200 ]]; then
    echo "ERROR: GitHub refused to move ${BRANCH} to ${NEW_COMMIT} (HTTP ${ref_status}: $(site_json message "$WORK_DIR/ref-update-response.json"))." >&2
    echo "       The update is never forced: if ${BRANCH} moved after ${BASE_COMMIT:0:12} was read," >&2
    echo "       that change was kept and nothing was published. Re-run to rebuild on the new head." >&2
    exit 1
fi
site_json sha "$WORK_DIR/ref-update-response.json" object.sha "$NEW_COMMIT" >/dev/null

if [[ "$SKIP_APPCAST_ITEM" != 1 ]]; then
    echo "✓ Published appcast.xml (build ${BUILD_ID}) + release.json in one commit: https://github.com/${SITE_REPO}/commit/${NEW_COMMIT}"
else
    echo "✓ Published release.json only (appcast skipped): https://github.com/${SITE_REPO}/commit/${NEW_COMMIT}"
fi
echo "Workers Builds deploys this single commit; verify the live files, not this commit."
