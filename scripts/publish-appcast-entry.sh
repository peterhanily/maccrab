#!/bin/bash
# Insert a locally generated, schema-validated Sparkle item through GitHub's
# optimistic-locking Contents API. No PUT occurs until both the fragment and the
# complete post-insertion feed have parsed successfully.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ITEM=""
SITE_REPO="${SITE_REPO:-}"
VERSION=""
BRANCH="main"

usage() {
    echo "usage: $0 --item FILE --site-repo OWNER/REPO --version X [--branch NAME]" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --item) [[ $# -ge 2 ]] || { usage; exit 2; }; ITEM="$2"; shift 2 ;;
        --site-repo) [[ $# -ge 2 ]] || { usage; exit 2; }; SITE_REPO="$2"; shift 2 ;;
        --version) [[ $# -ge 2 ]] || { usage; exit 2; }; VERSION="$2"; shift 2 ;;
        --branch) [[ $# -ge 2 ]] || { usage; exit 2; }; BRANCH="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$ITEM" && -f "$ITEM" && ! -L "$ITEM" ]] || { echo "ERROR: --item must be a regular no-link file" >&2; exit 2; }
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

# This is deliberately before curl: malformed/XXE/multi-item input cannot
# trigger even a GET, much less reach the authenticated PUT path.
BUILD_ID=$(run_xml_helper validate-item --item "$ITEM" --expected-version "$VERSION")

WORK_DIR=$(/usr/bin/mktemp -d /private/tmp/maccrab-appcast-publish.XXXXXX)
trap '/bin/rm -rf "$WORK_DIR"' EXIT HUP INT TERM
AUTH_CONFIG="$WORK_DIR/curl-auth"
RESPONSE="$WORK_DIR/response.json"
CURRENT_XML="$WORK_DIR/current.xml"
NEW_XML="$WORK_DIR/new.xml"
PAYLOAD="$WORK_DIR/payload.json"
PUT_RESPONSE="$WORK_DIR/put-response.json"

# Keep the PAT out of argv/process listings. The private config exists only in
# this mode-0700 temporary directory and is removed by the trap.
printf 'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n' \
    "$SITE_REPO_TOKEN" > "$AUTH_CONFIG"

API="https://api.github.com/repos/${SITE_REPO}/contents/appcast.xml?ref=${BRANCH}"
echo "Fetching current appcast.xml from ${SITE_REPO} (${BRANCH})..."
/usr/bin/curl -fsS --connect-timeout 10 --max-time 30 --max-filesize 6291456 \
    --config "$AUTH_CONFIG" "$API" --output "$RESPONSE"
response_size=$(/usr/bin/stat -f%z "$RESPONSE")
[[ "$response_size" -le 6291456 ]] || { echo "ERROR: GitHub response exceeds 6 MiB" >&2; exit 1; }

CURRENT_SHA=$(run_xml_helper decode-github-response --response "$RESPONSE" --output "$CURRENT_XML")

# The helper rejects duplicate Sparkle build identities, parses the current
# feed, injects exactly one item, then parses the full resulting feed before it
# writes NEW_XML. This closes the old regex-only XML publication boundary.
run_xml_helper inject \
    --item "$ITEM" \
    --current "$CURRENT_XML" \
    --output "$NEW_XML" \
    --expected-version "$VERSION" \
    --expected-build "$BUILD_ID"

MSG="Publish appcast entry for v${VERSION} (build ${BUILD_ID})"
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -c '
import base64, json, os, sys
message, xml_path, sha, branch, output = sys.argv[1:]
data = open(xml_path, "rb").read(4 * 1024 * 1024 + 1)
if len(data) > 4 * 1024 * 1024:
    raise SystemExit("new appcast exceeds 4 MiB")
payload = {"message": message, "content": base64.b64encode(data).decode("ascii"), "sha": sha, "branch": branch}
fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, separators=(",", ":"))
' "$MSG" "$NEW_XML" "$CURRENT_SHA" "$BRANCH" "$PAYLOAD"

echo "Publishing validated feed to ${SITE_REPO}/appcast.xml on ${BRANCH}..."
/usr/bin/curl -fsS --connect-timeout 10 --max-time 30 --max-filesize 1048576 \
    --config "$AUTH_CONFIG" \
    -X PUT \
    -H "Content-Type: application/json" \
    --data-binary "@$PAYLOAD" \
    "https://api.github.com/repos/${SITE_REPO}/contents/appcast.xml" \
    --output "$PUT_RESPONSE"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -c '
import json, re, sys
with open(sys.argv[1], "rb") as fh:
    response = json.load(fh)
url = response.get("commit", {}).get("html_url") if isinstance(response, dict) else None
if not isinstance(url, str) or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commit/[a-f0-9]{40}", url):
    message = response.get("message", response) if isinstance(response, dict) else response
    raise SystemExit(f"GitHub API did not return a valid commit: {message}")
print("✓ Published: " + url)
' "$PUT_RESPONSE"

echo "Cloudflare Pages will redeploy automatically; verify the live build id ${BUILD_ID}."
