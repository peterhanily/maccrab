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
#   1. Credential patterns in ADDED lines.
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

cd "$(cd "$(dirname "$0")/.." && pwd)"
command -v git >/dev/null 2>&1 || { echo "check-secrets: git not found" >&2; exit 2; }

MODE="diff"
BASE="${1:-origin/main}"
if [ "${1:-}" = "--tree" ]; then MODE="tree"; BASE=""; fi

# Findings go to a FILE, not a shell variable: the scanning pipelines run in
# subshells, so a variable set inside them is discarded on subshell exit.
FINDINGS="$(mktemp -t maccrab-secret-findings)"
SUBJECT="$(mktemp -t maccrab-secret-subject)"
trap 'rm -f "$FINDINGS" "$SUBJECT"' EXIT

if [ "$MODE" = "diff" ]; then
    if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
        echo "check-secrets: base ref '$BASE' not found — pass one explicitly" >&2
        exit 2
    fi
    # Added lines only, with the leading '+' stripped. `git diff` marks the
    # file for each hunk; keep the +++ header lines so a hit can be attributed.
    git diff "$BASE"...HEAD -- . \
        | grep -E '^\+\+\+ |^\+' > "$SUBJECT" || true
    DESC="added lines in ${BASE}...HEAD"
else
    # macOS ships bash 3.2 — no `mapfile`, hence the file-list pipeline.
    git ls-files -z | tr '\0' '\n' | grep -vE '^scripts/check-secrets\.sh$' \
        | tr '\n' '\0' | xargs -0 grep -InE '' 2>/dev/null > "$SUBJECT" || true
    DESC="all tracked files"
fi

# Report a hit with the file it belongs to. In diff mode we walk forward from
# the most recent `+++ b/<path>` header; in tree mode grep already prefixes it.
collect() {   # collect <label>
    local label="$1" line file=""
    while IFS= read -r line; do
        case "$line" in
            '+++ b/'*) file="${line#+++ b/}"; continue ;;
            '+++ '*)   file="${line#+++ }";   continue ;;
        esac
        case "$line" in *secret-scan:allow*) continue ;; esac
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
    if [ "$MODE" = "diff" ]; then
        grep -E "^\+\+\+ |$1" "$SUBJECT" | collect "$2" || true
    else
        grep -E "$1" "$SUBJECT" | collect "$2" || true
    fi
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
git ls-files --cached --ignored --exclude-standard 2>/dev/null \
    | while IFS= read -r f; do
        [ -z "$f" ] && continue
        printf '  tracked despite .gitignore (force-added?) → %s\n' "$f" >> "$FINDINGS"
      done || true

# ── 3. This operator's home path ────────────────────────────────────────
# Not `/Users/<anyone>/`: detection rules and tests reference other users'
# home paths legitimately, and flagging those buries the real signal. The leak
# is THIS machine's username appearing in committed content.
ME="$(id -un)"
if [ -n "$ME" ] && [ "$ME" != "root" ]; then
    scan_for "/Users/${ME}(/|\\b)" "operator home path (/Users/${ME})"
fi

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
