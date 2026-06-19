#!/bin/bash
# publish-cask.sh — Publish the locally-bumped Casks/maccrab.rb into the
# dedicated peterhanily/homebrew-maccrab tap repo via the GitHub Contents API.
#
# Why a separate tap repo + the Contents API:
#   The app repo (peterhanily/maccrab) used to double as the Homebrew tap.
#   When its main-branch history was force-pushed/rewritten, every existing
#   tap clone could no longer fast-forward — `brew update` fell back to a
#   rebase, failed, and left merge-conflict markers in maccrab.rb (unparseable
#   cask → install impossible). The Contents API creates exactly ONE
#   forward-only commit per call (never a force-push / rebase), so the tap is
#   always fast-forwardable. Mirrors publish-release-json.sh.
#
# Usage:
#   export TAP_REPO_TOKEN=...   # PAT with contents:write on homebrew-maccrab
#                               # (falls back to GH_TOKEN, then SITE_REPO_TOKEN)
#   scripts/publish-cask.sh
#
# Reads ./Casks/maccrab.rb and PUTs it to
# peterhanily/homebrew-maccrab/Casks/maccrab.rb on main.

set -euo pipefail

CASK_PATH="${CASK_PATH:-Casks/maccrab.rb}"
TAP_REPO="${TAP_REPO:-peterhanily/homebrew-maccrab}"
DEST_PATH="${DEST_PATH:-Casks/maccrab.rb}"
BRANCH="${BRANCH:-main}"
# Prefer a dedicated token; fall back to the broad-scope gh OAuth token, then
# the site PAT. Whichever is used needs contents:write on $TAP_REPO.
TOKEN="${TAP_REPO_TOKEN:-${GH_TOKEN:-${SITE_REPO_TOKEN:-}}}"

[[ -n "$TOKEN" ]] || {
    echo "ERROR: no token — set TAP_REPO_TOKEN (or GH_TOKEN / SITE_REPO_TOKEN) with write access to $TAP_REPO" >&2
    exit 2
}
[[ -f "$CASK_PATH" ]] || {
    echo "ERROR: $CASK_PATH not found — run from the repo root after the cask is bumped" >&2
    exit 1
}

# Never propagate the exact breakage this whole setup exists to prevent: refuse
# to publish a cask carrying unresolved merge-conflict markers.
if grep -qE '^(<<<<<<<|=======|>>>>>>>)' "$CASK_PATH"; then
    echo "ERROR: $CASK_PATH contains merge-conflict markers — refusing to publish" >&2
    exit 1
fi

VERSION=$(grep -E '^[[:space:]]*version[[:space:]]+"' "$CASK_PATH" \
          | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^"]*' | head -1 || true)
[[ -n "$VERSION" ]] || {
    echo "ERROR: couldn't parse version from $CASK_PATH" >&2
    exit 1
}

echo "Publishing $CASK_PATH to ${TAP_REPO}/${DEST_PATH} on $BRANCH (v$VERSION)..."

API="https://api.github.com/repos/${TAP_REPO}/contents/${DEST_PATH}"

# Current blob SHA (PUT requires it to update an existing file).
CURRENT=$(curl -sS -H "Authorization: Bearer $TOKEN" "${API}?ref=${BRANCH}" \
          | python3 -c 'import json,sys; print(json.load(sys.stdin).get("sha",""))' 2>/dev/null || echo "")

B64=$(base64 -i "$CASK_PATH")

PAYLOAD=$(python3 -c "
import json
sha = '$CURRENT'
payload = {
    'message': 'maccrab: bump cask to v$VERSION',
    'content': '''$B64'''.replace('\n', ''),
    'branch': '$BRANCH',
}
if sha:
    payload['sha'] = sha
print(json.dumps(payload))
")

RESPONSE=$(curl -sS -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -d "$PAYLOAD" \
    "$API")

COMMIT=$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("commit", {}).get("html_url", ""))' 2>/dev/null || echo "")

if [[ -n "$COMMIT" ]]; then
    echo "✓ Published cask: $COMMIT"
    echo "  brew install --cask peterhanily/maccrab/maccrab now serves v$VERSION"
else
    echo "ERROR: cask publish failed. Response:" >&2
    echo "$RESPONSE" >&2
    exit 1
fi
