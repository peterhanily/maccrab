#!/usr/bin/env bash
# check-secrets.sh — refuse to let a credential or a host-specific artifact
# reach the repository's committed content.
#
# WHY THIS EXISTS
#   `main` is public. Under the assurance loop, `dev` accumulates automated
#   commits and eventually squash-merges into `main`, so anything landing on
#   dev is on a path to publication. Nothing covered this: pre-release-audit.sh
#   PASS 13 confines ES env-block ACCESSORS in source rather than scanning
#   committed bytes, and the pre-push hook only runs ci-local.sh. .gitignore
#   stops accidents but not `git add -f`, and does nothing about a credential
#   pasted into a source file.
#
#   The two catastrophic-if-leaked secrets are the Sparkle EdDSA private key
#   (no rotation path — leaking it compromises auto-update for every existing
#   install) and the Developer ID certificate.
#
# WHY IT SCANS THE DIFF, NOT THE TREE
#   This repository legitimately contains around a hundred credential-shaped
#   strings. HoneyfileManager PLANTS fake AWS keys, GitHub tokens and private
#   keys as deception canaries — that is a shipped feature. The LLM and OTLP
#   sanitizer tests carry fake `sk-ant-…`, `AKIA…` and `xox…` values precisely
#   to prove the sanitizer redacts them. A whole-tree scan reports all of it,
#   every run, forever.
#
#   That is not a tuning problem, it is the wrong question. Those strings are
#   the baseline; nobody is changing them. What matters for a loop that
#   generates automated commits is what the commits ADD. So the default scan
#   is added lines in <base>..HEAD, which makes the existing corpus invisible
#   and every hit worth reading. A scanner people actually read is worth more
#   than a thorough one they switch off.
#
# WHAT IT CHECKS
#   1. Credential patterns in ADDED lines across every unpublished commit.
#   2. Files .gitignore excludes but which are tracked anyway (`git add -f`).
#      Whole-tree, because it is precise and this is how a key file or a
#      measurement artifact would actually arrive.
#   3. The operator's OWN home path in added lines. Not `/Users/<anyone>/` —
#      detection rules and tests reference other people's home paths for good
#      reason. The leak is this machine's username.
#
# WHAT THIS IS NOT
#   Pattern matching. It will not catch a novel credential format, a secret
#   split across lines, or one already in history before the base ref. A pass
#   means "this diff adds no known-shape secret", not "nothing ever leaked".
#
# USAGE
#   scripts/check-secrets.sh [base-ref]      default: origin/main
#   scripts/check-secrets.sh --tree          scan all tracked files (noisy here)
#
# ALLOWLIST
#   A line carrying  secret-scan:allow  is skipped. Use it for documented
#   non-secrets, and say why on the same line.
#
# Exit 0 clean, 1 findings, 2 environment problem.
set -euo pipefail
# Git history may contain arbitrary bytes; scan them without locale decoding.
export LC_ALL=C

cd "$(cd "$(dirname "$0")/.." && pwd)"
command -v git >/dev/null 2>&1 || { echo "check-secrets: git not found" >&2; exit 2; }

MODE="diff"
BASE="${1:-origin/main}"
if [ "${1:-}" = "--tree" ]; then MODE="tree"; BASE=""; fi

# Findings go to a FILE, not a shell variable: the scanning pipelines run in
# subshells, so a variable set inside them is discarded on subshell exit.
FINDINGS="$(mktemp -t maccrab-secret-findings)"
SUBJECT="$(mktemp -t maccrab-secret-subject)"
MATCHES="$(mktemp -t maccrab-secret-matches)"
IGNORED="$(mktemp -t maccrab-secret-ignored)"
trap 'rm -f "$FINDINGS" "$SUBJECT" "$MATCHES" "$IGNORED"' EXIT

if [ "$MODE" = "diff" ]; then
    if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
        echo "check-secrets: base ref '$BASE' not found — pass one explicitly" >&2
        exit 2
    fi
    # Inspect each commit: a later deletion must not hide a committed secret.
    # Added lines only, with the leading '+' stripped. `git diff` marks the
    # file for each hunk; keep the +++ header lines so a hit can be attributed.
    if ! git log --reverse -m --format= --no-ext-diff --no-textconv -p "$BASE"..HEAD -- . 2>/dev/null \
        | /usr/bin/awk '/^\+\+\+ |^\+/ {print}' > "$SUBJECT" 2>/dev/null; then
        echo "check-secrets: cannot read the complete unpublished history" >&2
        exit 2
    fi
    DESC="added lines across every commit in ${BASE}..HEAD"
else
    # Read every listed text input or fail. Links are inspected as literal
    # targets, never followed outside the checkout; binary contents are skipped.
    /usr/bin/python3 -I - > "$SUBJECT" <<'PY_TREE'
import os, pathlib, stat, subprocess, sys
limit = 16 * 1024 * 1024
try:
    paths = subprocess.check_output(["/usr/bin/git", "ls-files", "-z"], stderr=subprocess.DEVNULL, timeout=60)
    total = 0
    for encoded in paths.split(b"\0"):
        if not encoded:
            continue
        name = encoded.decode("utf-8")
        if name == "scripts/check-secrets.sh":
            continue
        if "\n" in name or "\r" in name:
            raise ValueError("unsupported filename")
        path = pathlib.Path(name)
        if path.parent.resolve() != path.parent.absolute():
            raise ValueError("redirected parent")
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            raw = os.readlink(path).encode("utf-8")
            after = path.lstat()
        elif stat.S_ISREG(before.st_mode):
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
                before_open = os.fstat(handle.fileno())
                if (before.st_dev, before.st_ino) != (before_open.st_dev, before_open.st_ino):
                    raise ValueError("input replaced")
                raw = handle.read(65536)
                if b"\0" not in raw:
                    if before.st_size > limit:
                        raise ValueError("text input too large")
                    raw += handle.read(limit + 1 - len(raw))
                after = os.fstat(handle.fileno())
        else:
            raise ValueError("unsupported input")
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
        if any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError("input changed")
        if b"\0" in raw:
            continue
        if len(raw) > limit or stat.S_ISREG(before.st_mode) and len(raw) != before.st_size:
            raise ValueError("incomplete input")
        total += len(raw)
        if total > 256 * 1024 * 1024:
            raise ValueError("text inventory too large")
        for number, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
            print(f"{name}:{number}:{line}")
except (OSError, ValueError, subprocess.SubprocessError):
    print("check-secrets: cannot read the complete tracked text inventory", file=sys.stderr)
    raise SystemExit(2)
PY_TREE
    DESC="all tracked files"
fi

# Report a hit with the file it belongs to. In diff mode we walk forward from
# the most recent `+++ b/<path>` header; in tree mode grep already prefixes it.
collect() {   # collect <label>
    local label="$1" line file="" historical_line_sha
    while IFS= read -r line; do
        case "$line" in
            '+++ b/'*) file="${line#+++ b/}"; continue ;;
            '+++ '*)   file="${line#+++ }";   continue ;;
        esac
        case "$line" in *secret-scan:allow*) continue ;; esac
        if [ "$MODE" = "diff" ] && [ "$file" = "Tests/MacCrabCoreTests/AlertTriggerRepresentationTests.swift" ]; then
            # Two pre-annotation sanitizer fixtures use public alphabet payloads.
            # Bind the exact added content (without diff '+' or newline), not
            # the file or its current annotations. Any changed byte fails.
            historical_line_sha=$(printf '%s' "${line#+}" | /usr/bin/shasum -a 256 2>/dev/null) || {
                echo "check-secrets: cannot verify historical fixture identity" >&2
                exit 2
            }
            case "${historical_line_sha%% *}" in
                # Deliberate Anthropic-shaped alphabet sanitizer fixture.
                e17438108215d22a05ce85ac0c3ddd1fb2ef139af8a5f5a1a3193521360ec917) continue ;;
                # Deliberate GitHub-shaped alphabet sanitizer fixture.
                4025d74bc418d5fb1b2922190a7e0887b1b71e06f0f08635a4d2e1b348a4e2f9) continue ;;
            esac
        fi
        if [ "$MODE" = "diff" ]; then
            printf '  %s → %s\n' "$label" "${file:-<unknown file>}" >> "$FINDINGS"
        else
            printf '  %s → %s\n' "$label" "${line%%:*}" >> "$FINDINGS"
        fi
    done
}

# In diff mode the +++ headers must survive the grep so attribution works, so
# every pattern is OR'd with the header pattern.
scan_for() {   # scan_for <extended-regex> <label>
    local pattern="$1" status=0
    if [ "$MODE" = "diff" ]; then pattern="^\+\+\+ |$pattern"; fi
    grep -E -- "$pattern" "$SUBJECT" > "$MATCHES" || status=$?
    if [ "$status" -gt 1 ]; then
        echo "check-secrets: cannot scan the complete subject" >&2
        exit 2
    fi
    collect "$2" < "$MATCHES"
}

# ── 1. Credential patterns ──────────────────────────────────────────────
# High-signal only. Deliberately NOT included: the Apple app-specific-password
# shape [a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}, which matches ordinary hyphenated
# English ("some-kind-of-thing") and fired on release notes, rule YAML and
# engine source. Its false-positive rate makes it worse than nothing.
PATTERNS='
-----BEGIN [A-Z ]*PRIVATE KEY-----
sk-ant-[A-Za-z0-9_-]{20,}
sk-[A-Za-z0-9]{32,}
AKIA[0-9A-Z]{16}
gh[pousr]_[A-Za-z0-9]{36,}
github_pat_[A-Za-z0-9_]{30,}
xox[baprs]-[A-Za-z0-9-]{10,}
AIza[0-9A-Za-z_-]{35}
glpat-[A-Za-z0-9_-]{20,}
'
while IFS= read -r pattern; do
    [ -z "$pattern" ] && continue
    scan_for "$pattern" "credential /$pattern/"
done <<EOF
$PATTERNS
EOF

# ── 2. Force-added files that .gitignore excludes ───────────────────────
# Whole-tree regardless of mode: precise, cheap, and this is the path by which
# a key file, a .env, or a host-specific measurement artifact actually arrives.
if ! git ls-files --cached --ignored --exclude-standard > "$IGNORED" 2>/dev/null; then
    echo "check-secrets: cannot inspect force-added ignored files" >&2
    exit 2
fi
while IFS= read -r f; do
    [ -z "$f" ] && continue
    printf '  tracked despite .gitignore (force-added?) → %s\n' "$f" >> "$FINDINGS"
done < "$IGNORED"

# ── 3. This operator's home path ────────────────────────────────────────
# Not `/Users/<anyone>/`: detection rules and tests reference other users'
# home paths legitimately, and flagging those buries the real signal. The leak
# is THIS machine's username appearing in committed content.
ME="$(id -un)"
if [ -n "$ME" ] && [ "$ME" != "root" ]; then
    scan_for "/Users/${ME}(/|\\b)" "operator home path"
fi

# A public policy can contain aggregates and evidence commitments, never a
# rich host capture. Inspect every version proposed for publication, including
# one later replaced by a safe HEAD. Do not print matching values.
/usr/bin/python3 -I - "$MODE" "$BASE" >> "$FINDINGS" <<'PY_BASELINE'
import json, math, pathlib, subprocess, sys

def git(*args):
    try:
        return subprocess.check_output(["/usr/bin/git", *args], stderr=subprocess.DEVNULL, timeout=60)
    except (OSError, subprocess.SubprocessError):
        print("check-secrets: cannot inspect complete public policy history", file=sys.stderr)
        raise SystemExit(2)

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

def finite_number(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite number")
    return result

mode, base = sys.argv[1:]
path = "docs/RELEASE_RESOURCE_BASELINE.json"
refs = ["HEAD"]
if mode == "diff":
    refs += git("rev-list", "--full-history", base + "..HEAD", "--", path).decode().splitlines()
seen = set()
working = pathlib.Path(path)
working_raw = None
if mode == "tree" and (working.exists() or working.is_symlink()):
    if working.resolve() != working.absolute() or not working.is_file():
        print("  redirected public reference policy → " + path)
    else:
        try:
            with working.open("rb") as handle:
                working_raw = handle.read(16 * 1024 * 1024 + 1)
            if len(working_raw) > 16 * 1024 * 1024:
                raise ValueError("policy too large")
        except (OSError, ValueError):
            print("check-secrets: cannot read public reference policy", file=sys.stderr)
            raise SystemExit(2)
        refs.insert(0, None)
for ref in refs:
    if ref is None:
        raw = working_raw
    else:
        tree = git("ls-tree", "-z", ref, "--", path)
        if not tree:
            continue
        metadata, returned_path = tree.rstrip(b"\0").split(b"\t", 1)
        file_mode, kind, oid = metadata.split()
        if kind != b"blob" or file_mode not in (b"100644", b"100755") or returned_path.decode() != path:
            print("  redirected public reference policy → " + path)
            continue
        if int(git("cat-file", "-s", oid.decode())) > 16 * 1024 * 1024:
            print("check-secrets: public reference policy exceeds the read bound", file=sys.stderr)
            raise SystemExit(2)
        raw = git("cat-file", "blob", oid.decode())
    if raw in seen:
        continue
    seen.add(raw)
    try:
        document = json.loads(raw, object_pairs_hook=unique_object, parse_float=finite_number, parse_constant=finite_number)
        if not isinstance(document, dict):
            raise ValueError("Public policy must be an object")
    except (ValueError, UnicodeDecodeError):
        print("  invalid public reference policy → " + path)
        continue
    forbidden = {"host", "host_end", "samples", "installed_engine", "installed_gui",
                 "machine_id_sha256", "process_start_abstime", "engine_pid",
                 "captured_at", "recorded_at", "recording_source_root", "completion"}
    def contains_private(value):
        if isinstance(value, dict):
            return bool(set(value) & forbidden) or any(contains_private(item) for item in value.values())
        return isinstance(value, list) and any(contains_private(item) for item in value)
    if contains_private(document):
        print("  private host telemetry in public reference history → " + path)
PY_BASELINE

if [ ! -s "$FINDINGS" ]; then
    echo "check-secrets: clean ($DESC)"
    exit 0
fi

echo "check-secrets: findings ($DESC)" >&2
sort -u "$FINDINGS" >&2
cat >&2 <<'EOF'

If any finding is a real credential, deleting the line is NOT enough — it
stays in git history and must be treated as compromised: rotate it first,
then scrub the history. If a finding is a documented non-secret, mark that
line with
  secret-scan:allow
and state why on the same line.
EOF
exit 1
