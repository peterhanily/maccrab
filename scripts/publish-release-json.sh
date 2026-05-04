#!/bin/bash
# publish-release-json.sh — Push the locally-generated release.json into
# the maccrab-site repo so https://maccrab.com/release.json serves
# authoritative version + rule + test counts.
#
# Eliminates the version-drift class of bug that the v1.8.0 external
# review caught (website still showed 1.7.12 / 929 tests post-release).
# Site JS fetches release.json on load; no human action needed to keep
# the marketing copy in sync with reality.
#
# Usage:
#   export SITE_REPO_TOKEN=...     # same PAT used for appcast publish
#   scripts/publish-release-json.sh
#
# Reads ./release.json (produced by build-release.sh) and PUTs it to
# peterhanily/maccrab-site/release.json on main.

set -euo pipefail

JSON_PATH="${JSON_PATH:-release.json}"
SITE_REPO="${SITE_REPO:-peterhanily/maccrab-site}"
BRANCH="${BRANCH:-main}"

[[ -n "${SITE_REPO_TOKEN:-}" ]] || {
    echo "ERROR: SITE_REPO_TOKEN env var not set" >&2; exit 2;
}
[[ -f "$JSON_PATH" ]] || {
    echo "ERROR: $JSON_PATH not found — run scripts/build-release.sh first" >&2
    exit 1;
}

echo "Publishing $JSON_PATH to ${SITE_REPO}/release.json on $BRANCH..."

API="https://api.github.com/repos/${SITE_REPO}/contents/release.json?ref=${BRANCH}"

# Get current SHA if file exists (PUT requires it for updates).
CURRENT=$(curl -sS -H "Authorization: Bearer $SITE_REPO_TOKEN" "$API" \
          | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("sha", ""))' 2>/dev/null || echo "")

VERSION=$(python3 -c "import json; print(json.load(open('$JSON_PATH'))['version'])")

B64=$(base64 -i "$JSON_PATH")

PAYLOAD=$(python3 -c "
import json,os
sha = '$CURRENT'
payload = {
    'message': f'release.json: bump to v$VERSION',
    'content': '''$B64'''.replace('\n',''),
    'branch': '$BRANCH',
}
if sha:
    payload['sha'] = sha
print(json.dumps(payload))
")

RESPONSE=$(curl -sS -X PUT \
    -H "Authorization: Bearer $SITE_REPO_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -d "$PAYLOAD" \
    "https://api.github.com/repos/${SITE_REPO}/contents/release.json")

COMMIT=$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("commit", {}).get("html_url", ""))' 2>/dev/null || echo "")

if [[ -n "$COMMIT" ]]; then
    echo "✓ Published: $COMMIT"
    echo ""
    echo "Cloudflare Pages will redeploy automatically. Verify in ~30-60s:"
    echo "  curl -s https://maccrab.com/release.json | python3 -m json.tool"
else
    echo "ERROR: Publish failed. Response:" >&2
    echo "$RESPONSE" >&2
    exit 1
fi
