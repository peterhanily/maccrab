#!/bin/bash
# publish-appcast-entry.sh — Insert a generated <item> into the site repo's
# appcast.xml by committing through the GitHub API.
#
# Usage:
#   export SITE_REPO_TOKEN=...     # fine-grained PAT, contents:write on site repo
#   scripts/publish-appcast-entry.sh \
#       --item /tmp/item.xml \
#       [--site-repo the site repo] \
#       [--version 1.3.5]
#
# What it does:
#   1. Fetches appcast.xml from the site repo via the GitHub Contents API
#   2. Inserts the new <item> immediately after <channel>'s <language> tag
#      (or after <description> if no <language>) so it lands as the newest entry
#   3. Commits the result back with a descriptive message
#   4. Cloudflare Pages auto-redeploys within ~30s
#
# Safe to re-run — if an <item> with the same sparkle:version already exists,
# this script refuses to publish.

set -euo pipefail

ITEM=""
SITE_REPO="${SITE_REPO:-}"
VERSION=""
BRANCH="main"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --item) ITEM="$2"; shift 2 ;;
        --site-repo) SITE_REPO="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --branch) BRANCH="$2"; shift 2 ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -n "${SITE_REPO_TOKEN:-}" ]] || { echo "ERROR: SITE_REPO_TOKEN env var not set" >&2; exit 2; }
[[ -n "$ITEM" && -f "$ITEM" ]]   || { echo "ERROR: --item must point to a readable file" >&2; exit 2; }

# Extract version from the item if --version wasn't passed
if [[ -z "$VERSION" ]]; then
    VERSION=$(grep -oE '<sparkle:version>[^<]+</sparkle:version>' "$ITEM" | \
              sed -E 's/<sparkle:version>([^<]+)<\/sparkle:version>/\1/' | head -1)
fi
[[ -n "$VERSION" ]] || { echo "ERROR: could not infer --version and not provided" >&2; exit 2; }

API="https://api.github.com/repos/${SITE_REPO}/contents/appcast.xml?ref=${BRANCH}"

echo "Fetching current appcast.xml from ${SITE_REPO} (${BRANCH})..."
RESPONSE=$(curl -sS -H "Authorization: Bearer $SITE_REPO_TOKEN" \
                    -H "Accept: application/vnd.github+json" "$API")

# Parse current content (base64) + SHA for optimistic locking
CURRENT_B64=$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["content"])' | tr -d '\n')
CURRENT_SHA=$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')
CURRENT_XML=$(echo "$CURRENT_B64" | base64 -d)

# Refuse to double-publish the same version.
if echo "$CURRENT_XML" | grep -qE "<sparkle:version>${VERSION}</sparkle:version>"; then
    echo "ERROR: appcast already contains <sparkle:version>${VERSION}</sparkle:version>. Refusing to publish twice." >&2
    exit 3
fi

# Insert item. Anchor after <language> or <description> — whichever is
# present in the current channel header. We use Python for the XML work
# because sed across newlines is a path of pain. Pass the current XML
# through a temp file (not a Python heredoc literal) because the XML can
# contain backslashes, triple-quotes, or unbalanced quotes from the CDATA
# release notes, any of which would corrupt a heredoc interpolation.
CURRENT_XML_FILE=$(mktemp -t maccrab-appcast-current.XXXXXX)
trap 'rm -f "$CURRENT_XML_FILE"' EXIT
printf '%s' "$CURRENT_XML" > "$CURRENT_XML_FILE"

NEW_XML=$(python3 -c '
import sys, re
item_path, current_path = sys.argv[1], sys.argv[2]
item = open(item_path).read().strip()
xml  = open(current_path).read()
# re.sub treats backslashes + digits in the replacement as backrefs,
# so escape any in the item before substitution.
def inject(m):
    return m.group(1) + "\n    " + item
anchors = [
    r"(<language>[^<]*</language>)",
    r"(<description>[^<]*</description>)",
    r"(<channel>)",
]
for pat in anchors:
    if re.search(pat, xml):
        xml = re.sub(pat, inject, xml, count=1)
        break
sys.stdout.write(xml)
' "$ITEM" "$CURRENT_XML_FILE")

# Base64 the new content and PUT via Contents API
NEW_B64=$(echo -n "$NEW_XML" | base64)
MSG="Publish appcast entry for v${VERSION}"
PAYLOAD=$(python3 -c '
import json, sys
print(json.dumps({
    "message": sys.argv[1],
    "content": sys.argv[2],
    "sha": sys.argv[3],
    "branch": sys.argv[4],
}))
' "$MSG" "$NEW_B64" "$CURRENT_SHA" "$BRANCH")

echo "Publishing to ${SITE_REPO}/appcast.xml on branch ${BRANCH}..."
curl -sS -X PUT \
    -H "Authorization: Bearer $SITE_REPO_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    --data "$PAYLOAD" \
    "https://api.github.com/repos/${SITE_REPO}/contents/appcast.xml" \
    | python3 -c '
import json, sys
r = json.load(sys.stdin)
if "commit" in r:
    print("✓ Published: " + r["commit"]["html_url"])
else:
    print("✗ GitHub API error:", r.get("message", r), file=sys.stderr)
    sys.exit(1)
'

echo ""
echo "Cloudflare Pages will redeploy automatically. Verify in ~30-60s:"
echo "  curl -s https://maccrab.com/appcast.xml | grep -A1 '<sparkle:version>${VERSION}'"
