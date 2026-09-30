#!/bin/bash
# Offline fixtures for scripts/publish-site-release.sh. A fake curl serves the
# GitHub Git Data API from a local bare repository, so the assertions read real
# Git history: one commit carrying both files, a non-forced ref update, a moved
# branch that fails loudly, and a Sparkle-less publish. No network, no token.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_ROOT=$(/usr/bin/mktemp -d /private/tmp/maccrab-site-publish-test.XXXXXX)
trap '/bin/rm -rf "$TMP_ROOT"' EXIT

TOKEN=github_pat_FAKE_OFFLINE_ONLY_site_publish  # secret-scan:allow — placeholder for the offline fake GitHub API; never a real token
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@invalid.example
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@invalid.example

pass_count=0
pass() { pass_count=$((pass_count + 1)); echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

SIG=$(/usr/bin/python3 -I -c 'import base64; print(base64.b64encode(bytes(64)).decode())')
cat > "$TMP_ROOT/notes.html" <<'HTML'
<p>Fixture notes.</p>
HTML
/usr/bin/python3 -I "$SCRIPT_DIR/_appcast_xml.py" generate \
    --version 1.2.2 --build-number 1.2.2.40 \
    --pub-date 'Sun, 02 Aug 2026 12:00:00 +0000' \
    --signature "$SIG" --length 17 --dmg-name MacCrab-v1.2.2.dmg \
    --notes-file "$TMP_ROOT/notes.html" > "$TMP_ROOT/old-item.xml"
/usr/bin/python3 -I "$SCRIPT_DIR/_appcast_xml.py" generate \
    --version 1.2.3 --build-number 1.2.3.42 \
    --pub-date 'Mon, 03 Aug 2026 12:00:00 +0000' \
    --signature "$SIG" --length 17 --dmg-name MacCrab-v1.2.3.dmg \
    --notes-file "$TMP_ROOT/notes.html" > "$TMP_ROOT/item.xml"
{
    printf '%s\n' '<?xml version="1.0" encoding="utf-8"?>' \
        '<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">' \
        '  <channel><title>MacCrab</title><description>Updates</description><language>en</language>'
    cat "$TMP_ROOT/old-item.xml"
    printf '%s\n' '  </channel>' '</rss>'
} > "$TMP_ROOT/seed-appcast.xml"
printf '{"version":"1.2.2","dmg":{"sha256":"%064d"}}\n' 0 > "$TMP_ROOT/seed-release.json"
printf '{"version":"1.2.3","dmg":{"sha256":"%064d"}}\n' 1 > "$TMP_ROOT/release.json"

# The fake speaks just enough of api.github.com for the publisher, backed by
# real Git plumbing. It records each request and whether the credential stayed
# out of argv inside a private config file.
cat > "$TMP_ROOT/fake-curl.py" <<'PY'
#!/usr/bin/python3
import base64, json, os, pathlib, re, stat, subprocess, sys

STATE = pathlib.Path("__STATE__")
SITE = STATE / "site.git"
PREFIX = "https://api.github.com/repos/owner/site/"
args = sys.argv[1:]


def git(*command, data=None, env=None):
    return subprocess.run(["/usr/bin/git", "--git-dir", str(SITE), *command], input=data,
                          capture_output=True, check=True, env={**os.environ, **(env or {})}).stdout


def value(flag):
    return args[args.index(flag) + 1] if flag in args else None


config = pathlib.Path(value("--config"))
token = (STATE / "token").read_text().strip()
method = value("-X") or "GET"
url = next(a for a in args if a.startswith("https://"))
data = value("--data-binary")
payload = json.loads(pathlib.Path(data[1:]).read_text()) if data else None
with open(STATE / "calls.jsonl", "a") as log:
    log.write(json.dumps({
        "method": method, "url": url, "payload": payload, "first": args[0],
        "token_in_argv": any(token in a for a in args),
        "config_private": stat.S_IMODE(config.stat().st_mode) == 0o600
        and stat.S_IMODE(config.parent.stat().st_mode) == 0o700,
        "config_has_token": f"Authorization: Bearer {token}" in config.read_text(),
        "config": str(config),
    }) + "\n")
assert url.startswith(PREFIX), url
path = url[len(PREFIX):]
status, body = 404, {"message": "Not Found"}


def head():
    return git("rev-parse", "refs/heads/main").decode().strip()


if method == "GET" and path == "git/ref/heads/main":
    status, body = 200, {"ref": "refs/heads/main", "object": {"type": "commit", "sha": head()}}
elif method == "GET" and path.startswith("git/commits/"):
    sha = path.rsplit("/", 1)[1]
    parents = git("rev-list", "--parents", "-n", "1", sha).decode().split()[1:]
    status, body = 200, {"sha": sha, "tree": {"sha": git("rev-parse", sha + "^{tree}").decode().strip()},
                         "parents": [{"sha": p} for p in parents]}
elif method == "GET" and (match := re.fullmatch(r"contents/appcast\.xml\?ref=([a-f0-9]{40})", path)):
    blob = git("rev-parse", match.group(1) + ":appcast.xml").decode().strip()
    content = base64.encodebytes(git("cat-file", "blob", blob)).decode()
    status, body = 200, {"type": "file", "encoding": "base64", "sha": blob, "content": content}
elif method == "POST" and path == "git/blobs":
    assert payload["encoding"] == "base64"
    sha = git("hash-object", "-w", "--stdin", data=base64.b64decode(payload["content"])).decode().strip()
    status, body = 201, {"sha": sha}
elif method == "POST" and path == "git/trees":
    index = {"GIT_INDEX_FILE": str(STATE / "fake-index")}
    git("read-tree", payload["base_tree"], env=index)
    for entry in payload["tree"]:
        git("update-index", "--add", "--cacheinfo", f'{entry["mode"]},{entry["sha"]},{entry["path"]}', env=index)
    status, body = 201, {"sha": git("write-tree", env=index).decode().strip()}
    os.unlink(STATE / "fake-index")
elif method == "POST" and path == "git/commits":
    parents = [x for parent in payload["parents"] for x in ("-p", parent)]
    sha = git("commit-tree", payload["tree"], *parents, "-m", payload["message"]).decode().strip()
    status, body = 201, {"sha": sha, "tree": {"sha": payload["tree"]},
                         "parents": [{"sha": p} for p in payload["parents"]],
                         "html_url": "https://github.com/owner/site/commit/" + sha}
elif method == "PATCH" and path == "git/refs/heads/main":
    if (STATE / "move-ref-before-patch").exists():
        # A concurrent site edit lands between the publisher's read and write.
        index = {"GIT_INDEX_FILE": str(STATE / "fake-index")}
        git("read-tree", head(), env=index)
        other = git("hash-object", "-w", "--stdin", data=b"<p>concurrent edit</p>\n").decode().strip()
        git("update-index", "--add", "--cacheinfo", f"100644,{other},index.html", env=index)
        tree = git("write-tree", env=index).decode().strip()
        os.unlink(STATE / "fake-index")
        moved = git("commit-tree", tree, "-p", head(), "-m", "concurrent site edit").decode().strip()
        git("update-ref", "refs/heads/main", moved)
        (STATE / "concurrent-commit").write_text(moved + "\n")
    current = head()
    fast_forward = subprocess.run(["/usr/bin/git", "--git-dir", str(SITE), "merge-base",
                                   "--is-ancestor", current, payload["sha"]]).returncode == 0
    if payload.get("force") is True or fast_forward:
        git("update-ref", "refs/heads/main", payload["sha"])
        status, body = 200, {"ref": "refs/heads/main", "object": {"type": "commit", "sha": payload["sha"]}}
    else:
        status, body = 422, {"message": "Update is not a fast forward"}

if "-f" in "".join(a for a in args if re.fullmatch(r"-[a-zA-Z]+", a)) and status >= 400:
    sys.stderr.write(f"curl: (22) The requested URL returned error: {status}\n")
    raise SystemExit(22)
encoded = json.dumps(body)
output = value("--output")
if output:
    pathlib.Path(output).write_text(encoded)
else:
    sys.stdout.write(encoded)
if value("-w") == "%{http_code}":
    sys.stdout.write(str(status))
PY

# Each case gets a fresh site whose main holds the previous release, plus an
# unrelated page so base_tree preservation is observable.
make_case() {
    local case_dir="$TMP_ROOT/$1" index
    /bin/mkdir -p "$case_dir/scripts"
    printf '%s\n' "$TOKEN" > "$case_dir/token"
    /usr/bin/git init -q --bare "$case_dir/site.git"
    index="$case_dir/seed-index"
    for file in appcast.xml release.json index.html; do
        case "$file" in
            appcast.xml) source="$TMP_ROOT/seed-appcast.xml" ;;
            release.json) source="$TMP_ROOT/seed-release.json" ;;
            index.html) printf '<p>site</p>\n' > "$case_dir/index.html"; source="$case_dir/index.html" ;;
        esac
        blob=$(/usr/bin/git --git-dir "$case_dir/site.git" hash-object -w "$source")
        GIT_INDEX_FILE="$index" /usr/bin/git --git-dir "$case_dir/site.git" \
            update-index --add --cacheinfo "100644,$blob,$file"
    done
    tree=$(GIT_INDEX_FILE="$index" /usr/bin/git --git-dir "$case_dir/site.git" write-tree)
    seed=$(/usr/bin/git --git-dir "$case_dir/site.git" commit-tree "$tree" -m 'site with v1.2.2')
    /usr/bin/git --git-dir "$case_dir/site.git" update-ref refs/heads/main "$seed"
    /bin/rm -f "$index"
    /usr/bin/sed "s#__STATE__#$case_dir#" "$TMP_ROOT/fake-curl.py" > "$case_dir/fake-curl"
    /bin/chmod 0755 "$case_dir/fake-curl"
    /bin/cp "$SCRIPT_DIR/_appcast_xml.py" "$case_dir/scripts/"
    # Production pins curl; only this disposable copy points at the fake.
    /usr/bin/sed "s#^CURL_BIN=/usr/bin/curl\$#CURL_BIN=$case_dir/fake-curl#" \
        "$SCRIPT_DIR/publish-site-release.sh" > "$case_dir/scripts/publish-site-release.sh"
    /bin/chmod 0755 "$case_dir/scripts/publish-site-release.sh"
    /usr/bin/grep -qx "CURL_BIN=$case_dir/fake-curl" "$case_dir/scripts/publish-site-release.sh" \
        || fail "fixture could not redirect the pinned curl"
    CASE_DIR="$case_dir"
    SEED_COMMIT="$seed"
}

run_publisher() {
    set +e
    /usr/bin/env -i PATH=/usr/bin:/bin HOME="$CASE_DIR" TMPDIR=/private/tmp LC_ALL=C LANG=C \
        SITE_REPO_TOKEN="$TOKEN" \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@invalid.example \
        GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@invalid.example \
        "$CASE_DIR/scripts/publish-site-release.sh" \
        --release-json "$TMP_ROOT/release.json" --site-repo owner/site --version 1.2.3 "$@" \
        > "$CASE_DIR/output.log" 2>&1
    publisher_status=$?
    set -e
    if /usr/bin/grep -qF "$TOKEN" "$CASE_DIR/output.log"; then fail "credential reached publisher output"; fi
}

site_git() { /usr/bin/git --git-dir "$CASE_DIR/site.git" "$@"; }

# Every request kept the token in a private, since-deleted config file and the
# only branch move was one explicit force=false PATCH.
check_calls() {
    /usr/bin/python3 -I - "$CASE_DIR/calls.jsonl" "$1" <<'PY'
import json, os, sys
calls = [json.loads(line) for line in open(sys.argv[1])]
expected_patches = int(sys.argv[2])
for call in calls:
    assert not call["token_in_argv"], call
    assert call["config_private"] and call["config_has_token"], call
    assert call["first"] == "-q", call
    assert not os.path.exists(call["config"]), call
assert not [c for c in calls if c["method"] in ("PUT", "DELETE")], "Contents API write or delete used"
patches = [c for c in calls if c["method"] == "PATCH"]
assert len(patches) == expected_patches, patches
for patch in patches:
    assert patch["payload"].get("force", "missing") is False, patch["payload"]
PY
}

echo "Site publisher: one commit, fast-forward only"

make_case combined
run_publisher --item "$TMP_ROOT/item.xml"
[ "$publisher_status" -eq 0 ] || { cat "$CASE_DIR/output.log" >&2; fail "combined publish failed"; }
new_head=$(site_git rev-parse refs/heads/main)
[ "$(site_git rev-list --parents -n 1 "$new_head")" = "$new_head $SEED_COMMIT" ] \
    || fail "publish did not add exactly one commit whose single parent is the read base"
[ "$(site_git diff-tree --no-commit-id --name-only -r "$SEED_COMMIT" "$new_head")" = $'appcast.xml\nrelease.json' ] \
    || fail "the one commit does not carry exactly appcast.xml and release.json"
site_git cat-file blob "$new_head:release.json" | /usr/bin/cmp -s - "$TMP_ROOT/release.json" \
    || fail "published release.json differs from the local bytes"
site_git cat-file blob "$new_head:appcast.xml" > "$CASE_DIR/published-appcast.xml"
for build in 1.2.3.42 1.2.2.40; do
    /usr/bin/grep -qF "<sparkle:version>$build</sparkle:version>" "$CASE_DIR/published-appcast.xml" \
        || fail "merged appcast lacks build $build"
done
[ "$(site_git rev-parse "$new_head:index.html")" = "$(site_git rev-parse "$SEED_COMMIT:index.html")" ] \
    || fail "tree was not built on base_tree"
check_calls 1
pass "appcast.xml + release.json land in one fast-forward commit (force=false, token only in private config)"

make_case moved-base
: > "$CASE_DIR/move-ref-before-patch"
run_publisher --item "$TMP_ROOT/item.xml"
[ "$publisher_status" -ne 0 ] || fail "publisher reported success after its base ref moved"
concurrent=$(/bin/cat "$CASE_DIR/concurrent-commit")
[ "$(site_git rev-parse refs/heads/main)" = "$concurrent" ] \
    || fail "moved-base publish overwrote the concurrent site commit"
[ "$(site_git rev-parse "$concurrent:release.json")" = "$(site_git rev-parse "$SEED_COMMIT:release.json")" ] \
    || fail "moved-base publish changed release.json anyway"
/usr/bin/grep -q 'HTTP 422: Update is not a fast forward' "$CASE_DIR/output.log" \
    || fail "moved-base refusal did not surface GitHub's reason"
/usr/bin/grep -q 'never forced' "$CASE_DIR/output.log" \
    || fail "moved-base refusal did not explain that nothing was overwritten"
check_calls 1
pass "a branch moved after the read fails loudly and keeps the concurrent commit"

make_case skip-appcast
run_publisher --skip-appcast
[ "$publisher_status" -eq 0 ] || { cat "$CASE_DIR/output.log" >&2; fail "release.json-only publish failed"; }
new_head=$(site_git rev-parse refs/heads/main)
[ "$(site_git rev-list --parents -n 1 "$new_head")" = "$new_head $SEED_COMMIT" ] \
    || fail "release.json-only publish did not add exactly one child of the base"
[ "$(site_git diff-tree --no-commit-id --name-only -r "$SEED_COMMIT" "$new_head")" = "release.json" ] \
    || fail "--skip-appcast changed something other than release.json"
! /usr/bin/grep -q 'appcast' "$CASE_DIR/calls.jsonl" \
    || fail "--skip-appcast still read the appcast"
check_calls 1
pass "--skip-appcast (release.sh SKIP_APPCAST=1) publishes release.json alone"

make_case no-item
run_publisher
[ "$publisher_status" -ne 0 ] || fail "publisher accepted neither --item nor --skip-appcast"
[ ! -e "$CASE_DIR/calls.jsonl" ] || fail "missing --item reached the network"
make_case wrong-version
printf '{"version":"1.2.2"}\n' > "$CASE_DIR/stale-release.json"
set +e
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$CASE_DIR" SITE_REPO_TOKEN="$TOKEN" \
    "$CASE_DIR/scripts/publish-site-release.sh" --release-json "$CASE_DIR/stale-release.json" \
    --site-repo owner/site --version 1.2.3 --skip-appcast > "$CASE_DIR/output.log" 2>&1
wrong_version_status=$?
set -e
[ "$wrong_version_status" -ne 0 ] || fail "publisher accepted a release.json for another version"
[ ! -e "$CASE_DIR/calls.jsonl" ] || fail "stale release.json reached the network"
pass "a missing item or another version's release.json fails before any request"

echo "PASS: $pass_count site publisher fixtures"
