#!/bin/bash
# release.sh — One-command local release: build, sign, notarize, publish
#
# Usage:
#   ./scripts/release.sh 1.1.0
#
# Requires: DEVELOPER_ID, APPLE_ID, APPLE_TEAM_ID, NOTARIZE_PASSWORD
# Set these in ~/.maccrab-release-env (sourced automatically) or export them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION=""
SKIP_PRERELEASE=0
# Re-spinning a version used to die at `git tag` ("tag already exists") AFTER the
# full build + notarize had burnt ~15 minutes, leaving the release half-done with
# no way forward but manual surgery. --respin is the explicit opt-in to re-point
# an existing tag at the new HEAD.
RESPIN=0
# The branch a release may be cut from. Nothing checked this: `git tag` tags HEAD
# of whatever branch is checked out and the script then pushed the `main` REF, so
# a release cut from `dev` (the day-to-day branch here) produced a tag pointing at
# a commit not reachable from the public default branch — and `gh release create`
# builds the release from that tag.
RELEASE_BRANCH="${RELEASE_BRANCH:-main}"
for arg in "$@"; do
    case "$arg" in
        --skip-prerelease-check) SKIP_PRERELEASE=1 ;;
        --respin) RESPIN=1 ;;
        -*) echo "Unknown flag: $arg"; exit 1 ;;
        *) [ -z "$VERSION" ] && VERSION="$arg" ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> [--skip-prerelease-check]"
    echo "Example: $0 1.1.0"
    exit 1
fi

cd "$PROJECT_DIR"

# Post-publish failures used to be logged and swallowed: each of Steps 6 / 6b /
# 6c / 6d printed "! ... failed, run it manually" and the script still ended with
# "MacCrab v$VERSION Released!" and exit 0. That is how a release can ship while
# https://maccrab.com/release.json still advertises the PREVIOUS version, its
# DMG sha256 and its test counts — the publish soft-failed, nothing ever re-read
# the LIVE file, and the release was declared successful.
#
# Collect failures here and fail the whole release at the END rather than at the
# point of failure: a dead SITE_REPO_TOKEN must not also strand the tap cask
# (Step 6d) or the appcast. Every remaining publish step still gets its chance;
# the script just refuses to call the release good.
RELEASE_FAILURES=""
RELEASE_FAILURE_COUNT=0
release_fail() {
    RELEASE_FAILURE_COUNT=$(( RELEASE_FAILURE_COUNT + 1 ))
    RELEASE_FAILURES="${RELEASE_FAILURES}    - $1"$'\n'
    echo "  ✗ $1" >&2
}

# Source credentials from env file if it exists
ENV_FILE="$HOME/.maccrab-release-env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading credentials from $ENV_FILE"
    source "$ENV_FILE"
fi

# v1.18: derive GitHub tokens from the login-Keychain git credential when not
# explicitly set. In the field the standalone SITE_REPO_TOKEN AND the gh OAuth
# token both expired, which (a) aborted this script at Step 0a and (b) 401'd
# `gh release create` mid-release. The git credential that `git push` already
# uses is API-valid + repo-write for both maccrab and maccrab-site, so falling
# back to it removes the release's dependence on separately-maintained tokens
# that silently rot. Export GH_TOKEN / SITE_REPO_TOKEN to override.
_maccrab_git_pat() { printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p'; }
_MACCRAB_PAT="$(_maccrab_git_pat || true)"
if [ -n "${_MACCRAB_PAT:-}" ]; then
    export GH_TOKEN="${GH_TOKEN:-$_MACCRAB_PAT}"
    # The Keychain git credential is what `git push` already uses successfully
    # for BOTH maccrab and maccrab-site / homebrew-maccrab, so it's the reliable
    # source for the publish-to-other-repo tokens. The standalone SITE_REPO_TOKEN
    # in ~/.maccrab-release-env rotted in the field (dead PAT → 401 → the appcast
    # / release.json publish silently failed, the v1.20.0 GA hit exactly this).
    # PREFER the live credential over a possibly-stale env value, not the reverse.
    export SITE_REPO_TOKEN="$_MACCRAB_PAT"
    export TAP_REPO_TOKEN="${TAP_REPO_TOKEN:-$_MACCRAB_PAT}"
    echo "  ✓ GitHub tokens available (Keychain git credential preferred for site/tap publish)"
fi
unset _MACCRAB_PAT

# Verify credentials
if [ -z "${DEVELOPER_ID:-}" ]; then
    echo "ERROR: DEVELOPER_ID not set."
    echo ""
    echo "Either export it or create ~/.maccrab-release-env with:"
    echo '  export DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"'
    echo '  export APPLE_ID="your@email.com"'
    echo '  export APPLE_TEAM_ID="TEAMID"'
    echo '  export NOTARIZE_PASSWORD="xxxx-xxxx-xxxx-xxxx"'
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  MacCrab v$VERSION Release                       "
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Step 0a: appcast publishing precondition. v1.10.0-rc audit fix:
# step 6 below auto-publishes the appcast entry to the site repo
# when SITE_REPO_TOKEN is set, otherwise soft-fails with a warning.
# A soft-fail at minute ~12 of the release after the operator has
# already burnt notarization + DMG time is too late to recover —
# field-observed multiple times: "everything looked green but
# existing v1.x users never received the update." Now: refuse to
# start if the token is missing AND the operator hasn't explicitly
# opted out via SKIP_APPCAST=1. Catches the gap before any work
# is wasted.
if [ -z "${SITE_REPO_TOKEN:-}" ] && [ "${SKIP_APPCAST:-0}" != "1" ]; then
    echo "ERROR: SITE_REPO_TOKEN env var not set and SKIP_APPCAST != 1." >&2
    echo "" >&2
    echo "Without one of these, step 6 (Sparkle appcast publish) will not" >&2
    echo "run, and existing v1.x users WILL NOT receive v$VERSION via" >&2
    echo "auto-update — only the brew-upgrade path will deliver the new" >&2
    echo "version to them." >&2
    echo "" >&2
    echo "Either:" >&2
    echo "  - Add SITE_REPO_TOKEN to ~/.maccrab-release-env (recommended)" >&2
    echo "  - Or set SKIP_APPCAST=1 to confirm an intentional skip" >&2
    echo "    (e.g. internal-only / dry-run releases)" >&2
    exit 1
fi

# Step 0b: Pre-release check — enforce RELEASE_CHECKLIST.md items so the
# pipeline refuses to ship out-of-sync versions, stale notes, or broken
# localizations. Warnings still proceed; hard errors abort.
echo "Step 0/6: Pre-release check..."
if [ "$SKIP_PRERELEASE" = "1" ]; then
    echo "  (skipped via --skip-prerelease-check)"
else
    "$SCRIPT_DIR/prerelease-check.sh" "$VERSION" || {
        echo "Pre-release check failed — fix the errors above or run with --skip-prerelease-check to override (not recommended)"
        exit 1
    }
fi

# Step 0b: Architectural-invariants audit (v1.6.19). Catches the
# wire-the-orphans bug class and AlertSink-bypass regressions BEFORE
# they ship. Sister script to prerelease-check.sh: that one verifies
# manifest sync, this one verifies code structure.
echo "Step 0b/6: Architectural audit..."
"$SCRIPT_DIR/pre-release-audit.sh" || {
    echo "Architectural audit failed — fix the structural issues above before shipping"
    exit 1
}

# Step 1: Tests
#
# Pre-fix: `swift test 2>&1 | grep "Test run with"` matched both
# pass AND fail summary lines (Swift Testing prints the same prefix
# in either case), so the OR-chain only fired when grep matched
# nothing — i.e., the test runner crashed. Any test-suite failure
# was silently treated as success and the release shipped broken.
# Now: capture the swift test exit code FIRST, then report.
echo "Step 1/6: Running tests..."
if ! swift test; then
    echo "Tests failed — fix and re-run release.sh"
    exit 1
fi

# Step 2: Rule compilation
echo "Step 2/6: Compiling rules..."
python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir .build/compiled_rules 2>&1 | tail -1

# Step 2b: Regenerate README rule-count table + docs/COVERAGE.md so
# they match the YAML tree being released. v1.10 shipped with stale
# numbers in the README's hand-written coverage paragraph; auto-gen
# closes that drift window.
echo "Step 2b/6: Regenerating coverage docs..."
python3 scripts/coverage_matrix.py --update-readme README.md Rules/
python3 scripts/generate-coverage-doc.py > docs/COVERAGE.md
if ! git diff --quiet -- README.md docs/COVERAGE.md; then
    echo "  README.md / docs/COVERAGE.md changed — staging diff for the release commit"
    git add README.md docs/COVERAGE.md
fi

# Step 3: Build DMG
echo "Step 3/5: Building DMG..."
# v1.18 (sysext-zombie fix): give SHIPPED builds a DETERMINISTIC, monotonic
# CFBundleVersion (VERSION + commit count) instead of build-release.sh's
# per-second epoch. Re-running a release on the same commit then reuses the
# same (version, build) tuple, so sysextd does not orphan a fresh
# "terminated waiting to uninstall on reboot" zombie for an identical
# rebuild (the audit found ~50 such never-reaped entries). The per-second
# epoch stays as build-release.sh's fallback for the dev loop (`make dev`
# rebuilds the SAME VERSION with changed code and needs a distinct tuple
# each time to force sysextd to replace the active extension).
export BUILD_NUMBER="${VERSION}.$(git rev-list --count HEAD)"
echo "  Deterministic CFBundleVersion: $BUILD_NUMBER"
VERSION="$VERSION" ./scripts/build-release.sh

# (v1.6.11) PKG build removed — productbuild's distribution-XML
# pkg-ref name didn't match the component pkg filename, producing
# a 1.9KB stub archive that opened in Installer.app but contained
# no payload. DMG + Homebrew are the supported install paths.

# Step 4: Update Homebrew formulae
#
# The repo historically has TWO cask files — homebrew/maccrab.rb (legacy,
# in-tree docs) and Casks/maccrab.rb (what the Homebrew tap actually
# reads when this repo is tapped via `brew tap peterhanily/maccrab`).
# Pre-v1.6.14 the script only updated homebrew/maccrab.rb, so every
# release since v1.6.5 landed with a stale Casks/maccrab.rb — brew
# users saw old versions for nine releases before anyone noticed.
# Both files are now updated in lockstep.
DMG_PATH=".build/MacCrab-v$VERSION.dmg"
if [ -f "$DMG_PATH" ]; then
    echo "Step 4/5: Updating Homebrew formulae..."
    SHA=$(shasum -a 256 "$DMG_PATH" | awk '{print $1}')
    for formula in homebrew/maccrab.rb Casks/maccrab.rb; do
        if [ -f "$formula" ]; then
            sed -i '' "s/version \".*\"/version \"$VERSION\"/" "$formula"
            sed -i '' "s/sha256 .*/sha256 \"$SHA\"/" "$formula"
            echo "  Updated $formula (sha256: ${SHA:0:16}...)"
        fi
    done
fi

# Step 5: Create GitHub release
echo "Step 5/5: Creating GitHub release..."
# release.json is regenerated by build-release.sh (:1125) with the freshly built
# DMG's sha256 + size, but it was never staged — so every tag pointed at a commit
# whose release.json still carried the PREVIOUS build's hash. v1.21.5's tagged
# tree says 6611efa8 while the DMG that actually shipped is 9eb6f493. Stage it
# alongside the casks so the tagged tree describes the artifact being tagged.
git add homebrew/maccrab.rb Casks/maccrab.rb release.json 2>/dev/null || true
# Step 5a: PRE-TAG artifact/manifest consistency gate.
#
# The cross-source SHA check (Step 6c) ran AFTER `git tag`, `git push` and
# `gh release create`, only when SITE_REPO_TOKEN was set, and never exited
# non-zero — it could observe divergence but structurally could not prevent it.
# Assert HERE, while nothing has been published and nothing is tagged, that
# release.json and both casks describe the DMG we are about to ship. Any
# mismatch aborts before a single byte reaches users.
gate_dmg_sha=$(shasum -a 256 "$DMG_PATH" | awk '{print $1}')
gate_json_sha=$(grep -oE '"sha256"[[:space:]]*:[[:space:]]*"[a-f0-9]{64}"' release.json 2>/dev/null | head -1 | grep -oE '[a-f0-9]{64}' || true)
if [ "$gate_json_sha" != "$gate_dmg_sha" ]; then
    echo "  ✗ release.json sha256 ($gate_json_sha) != built DMG ($gate_dmg_sha)" >&2
    echo "    Re-run scripts/build-release.sh so release.json describes THIS DMG." >&2
    exit 1
fi
for gate_cask in Casks/maccrab.rb homebrew/maccrab.rb; do
    [ -f "$gate_cask" ] || continue
    gate_cask_sha=$(grep -oE 'sha256[[:space:]]+"[a-f0-9]{64}"' "$gate_cask" | head -1 | grep -oE '[a-f0-9]{64}' || true)
    if [ "$gate_cask_sha" != "$gate_dmg_sha" ]; then
        echo "  ✗ $gate_cask sha256 ($gate_cask_sha) != built DMG ($gate_dmg_sha)" >&2
        echo "    brew install --cask would fail checksum verification for every user." >&2
        exit 1
    fi
done
echo "  ✓ Pre-tag gate: release.json + casks all describe DMG ${gate_dmg_sha:0:16}..."

git diff --cached --quiet || git commit -m "chore: update Homebrew formula to v$VERSION"

# Nothing tracked may be left uncommitted at tag time — that is exactly how
# release.json drifted out of the tagged tree. Tracked-file check only
# (--untracked-files=no) so scratch files in a working repo don't block a
# release, while a generated-but-unstaged manifest does.
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "  ✗ Tracked files are still modified after the release commit:" >&2
    git status --porcelain --untracked-files=no >&2
    echo "    Commit or stash them — the tag must describe the tree being shipped." >&2
    exit 1
fi
# Branch guard. A tag cut from a non-release branch points at a commit that need
# not be reachable from main, and `gh release create` builds the published
# artifact from that tag — so the shipped binary's source need not be public.
current_branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "DETACHED")
if [ "$current_branch" != "$RELEASE_BRANCH" ]; then
    echo "  ✗ On branch '$current_branch' but releases must be cut from '$RELEASE_BRANCH'." >&2
    echo "    Merge to $RELEASE_BRANCH and re-run, or set RELEASE_BRANCH=$current_branch to" >&2
    echo "    override deliberately." >&2
    exit 1
fi

# Existing-tag handling. Pre-fix `git tag` simply failed here under `set -e`,
# aborting the release after the build + notarize had already completed.
if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then
    if [ "$RESPIN" = "1" ]; then
        echo "  Re-spin: moving tag v$VERSION from $(git rev-parse --short "v$VERSION") to $(git rev-parse --short HEAD)"
        git tag -d "v$VERSION"
    else
        echo "  ✗ Tag v$VERSION already exists (at $(git rev-parse --short "v$VERSION"))." >&2
        echo "    Bump the version, or pass --respin to re-point it at this build." >&2
        exit 1
    fi
fi

# Annotated — and signed when a signing key is configured — tags. Every release
# tag through v1.21.5 is a LIGHTWEIGHT ref: `git tag -v` reports "cannot verify a
# non-tag object of type commit", so no release carries a tagger identity, a
# message, or any cryptographic binding to the maintainer, and anyone with repo
# write can silently move one. Annotated is the floor; signing is applied when
# available rather than made mandatory, because an unconditional `git tag -s` on
# a machine with no user.signingkey would hard-fail every release.
if [ -n "$(git config --get user.signingkey || true)" ]; then
    git tag -s "v$VERSION" -m "MacCrab v$VERSION"
    echo "  ✓ Signed annotated tag v$VERSION"
else
    echo "  ! No git user.signingkey configured — creating an ANNOTATED (unsigned) tag." >&2
    echo "    Enable signing so releases are verifiable by users and mirrors:" >&2
    echo "      git config gpg.format ssh && git config user.signingkey ~/.ssh/id_ed25519.pub" >&2
    git tag -a "v$VERSION" -m "MacCrab v$VERSION"
fi

# Push THIS commit to the release branch explicitly, and only the new tag.
# `git push origin main --tags` pushed the local `main` ref — which need not
# contain HEAD — plus every stray local tag in the repo.
git push origin "HEAD:refs/heads/$RELEASE_BRANCH"
if [ "$RESPIN" = "1" ]; then
    git push --force origin "refs/tags/v$VERSION"
else
    git push origin "refs/tags/v$VERSION"
fi

# Upload release artifacts (DMG only — PKG dropped in v1.6.11)
ARTIFACTS=""
[ -f ".build/MacCrab-v$VERSION.dmg" ] && ARTIFACTS=".build/MacCrab-v$VERSION.dmg"

if command -v gh &>/dev/null && [ -n "$ARTIFACTS" ]; then
    # v1.21.5: publish the curated RELEASE_NOTES/v<X>.md (the file Step 0's
    # prerelease-check already requires for GA releases) instead of GitHub's
    # --generate-notes commit list. Pre-fix, every release shipped with bare
    # auto-generated notes while the polished file only reached Sparkle users
    # via the appcast — the v1.21.4 GA had to be repaired post-hoc with
    # `gh release edit --notes-file`.
    NOTES_FILE="RELEASE_NOTES/v$VERSION.md"
    if [ -f "$NOTES_FILE" ]; then
        gh release create "v$VERSION" $ARTIFACTS \
            --title "MacCrab v$VERSION" \
            --notes-file "$NOTES_FILE"
        echo "  ✓ Release notes: $NOTES_FILE"
    else
        echo "  ! WARNING: $NOTES_FILE not found — falling back to GitHub auto-generated notes." >&2
        echo "    Write the curated notes, then repair with:" >&2
        echo "      gh release edit v$VERSION --notes-file $NOTES_FILE" >&2
        gh release create "v$VERSION" $ARTIFACTS \
            --title "MacCrab v$VERSION" \
            --generate-notes
    fi
    echo ""
    echo "  ✓ GitHub release created: https://github.com/peterhanily/maccrab/releases/tag/v$VERSION"
else
    echo ""
    echo "  Create release manually at: https://github.com/peterhanily/maccrab/releases/new?tag=v$VERSION"
    echo "  Upload: $ARTIFACTS"
fi

# Step 6: Publish appcast entry. Pre-fix this script stopped after
# `gh release create` and the operator had to remember to run
# generate-appcast-entry.sh + publish-appcast-entry.sh manually. The
# procedural gap meant several point releases shipped to GitHub but
# never reached existing users' Sparkle clients. Now: always try.
# Soft-fail if SITE_REPO_TOKEN is missing (log + skip; release stays
# successful) or SKIP_APPCAST=1 was passed (CI / manual override).
if [ "${SKIP_APPCAST:-0}" = "1" ]; then
    echo ""
    echo "  Step 6/6: Skipping appcast publish (SKIP_APPCAST=1)"
elif [ -n "${SITE_REPO_TOKEN:-}" ] && [ -f "$DMG_PATH" ]; then
    echo ""
    echo "Step 6/6: Publishing appcast entry..."
    SITE_REPO="${SITE_REPO:-peterhanily/maccrab-site}"
    APPCAST_ITEM=$(mktemp -t maccrab-appcast-item.XXXXXX.xml)
    if "$SCRIPT_DIR/generate-appcast-entry.sh" \
            --dmg "$DMG_PATH" --version "$VERSION" \
            > "$APPCAST_ITEM"; then
        if SITE_REPO_TOKEN="$SITE_REPO_TOKEN" \
                "$SCRIPT_DIR/publish-appcast-entry.sh" \
                --item "$APPCAST_ITEM" \
                --site-repo "$SITE_REPO" \
                --version "$VERSION"; then
            echo "  ✓ Appcast entry published; existing v1.x users will see the update within ~30s"
        else
            echo "  ! Appcast publish failed — run 'scripts/publish-appcast-entry.sh --item $APPCAST_ITEM' manually" >&2
        fi
    else
        echo "  ! Appcast generate failed — fix Sparkle sign_update + private key and retry" >&2
    fi
    rm -f "$APPCAST_ITEM"

    # Step 6b: Push the freshly built release.json into the site repo.
    # publish-release-json.sh has existed since v1.8 (created exactly
    # to fix a class of v1.7.12 / 929-tests post-release drift bug) but
    # was never wired into release.sh, so https://maccrab.com/release.json
    # silently lagged the actual release every cycle. v1.10.1 closed
    # that gap by adding this step. The site's JSON-LD softwareVersion +
    # the JS-rendered version pill both read this file.
    echo ""
    echo "Step 6b: Publishing release.json to site..."
    if SITE_REPO_TOKEN="$SITE_REPO_TOKEN" SITE_REPO="$SITE_REPO" \
            "$SCRIPT_DIR/publish-release-json.sh"; then
        echo "  ✓ release.json pushed to the site repo"
        # Verify the PUBLISHED file, not the local one. Step 6c below only ever
        # read ./release.json — which build-release.sh regenerated minutes
        # earlier from this very DMG, so it always agrees with itself and can
        # NEVER detect that maccrab.com is serving a stale file. Poll the live
        # URL until Cloudflare Pages has redeployed (~30-60s), then assert both
        # the version and the DMG sha256 the site actually advertises.
        published_ok=0
        live_ver=""
        live_sha=""
        for _ in $(seq 1 12); do
            live=$(curl -fsS --max-time 10 "https://maccrab.com/release.json" 2>/dev/null || true)
            live_ver=$(printf '%s' "$live" | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/' || true)
            live_sha=$(printf '%s' "$live" | grep -oE '"sha256"[[:space:]]*:[[:space:]]*"[a-f0-9]{64}"' | head -1 | grep -oE '[a-f0-9]{64}' || true)
            if [ "$live_ver" = "$VERSION" ] && [ "$live_sha" = "$SHA" ]; then
                published_ok=1
                break
            fi
            sleep 10
        done
        if [ "$published_ok" = "1" ]; then
            echo "  ✓ https://maccrab.com/release.json serves v$VERSION / sha ${SHA:0:16}..."
        else
            release_fail "maccrab.com/release.json still does not serve v$VERSION + sha ${SHA:0:16}... after ~2min (live: version=${live_ver:-<unreadable>} sha=${live_sha:0:16}) — the site is advertising a DIFFERENT build's hash to anyone verifying their download. Re-run 'SITE_REPO_TOKEN=<pat> scripts/publish-release-json.sh' and re-check with: curl -s https://maccrab.com/release.json"
        fi
    else
        release_fail "release.json publish failed — run 'SITE_REPO_TOKEN=<pat> scripts/publish-release-json.sh' manually; maccrab.com is still advertising the PREVIOUS release"
    fi

    # Step 6c: Cross-source SHA sanity check. v1.12.7 shipped with
    # release.json's SHA pointing at RC2's DMG (96d408db...) while
    # the GitHub release asset and Casks/maccrab.rb correctly pointed
    # at RC3's DMG (7c862c29...) — the squash-merge flow had restored
    # a pre-RC3 release.json snapshot and nobody noticed until a
    # post-publish manual check. v1.12.8 codifies the check: after
    # both publish steps land, diff the three sources of truth for
    # the DMG SHA. Three sources must agree:
    #   1. release.json on the local repo (just pushed to site)
    #   2. Casks/maccrab.rb (just bumped + pushed)
    #   3. GitHub release asset's recorded digest
    # If any disagree, the release is internally inconsistent and
    # users may end up with conflicting integrity signals.
    echo ""
    echo "Step 6c: Cross-source SHA sanity check..."
    # || true so set -e + pipefail don't abort the post-publish step
    # when grep finds nothing (we WANT to fall through and report).
    local_release_sha=$(grep -oE '"sha256":\s*"[a-f0-9]{64}"' release.json 2>/dev/null | head -1 | grep -oE '[a-f0-9]{64}' || true)
    cask_sha=$(grep -oE 'sha256\s+"[a-f0-9]{64}"' Casks/maccrab.rb 2>/dev/null | head -1 | grep -oE '[a-f0-9]{64}' || true)
    gh_release_sha=$(gh release view "v$VERSION" --json assets --jq '.assets[0].digest' 2>/dev/null | sed 's/^sha256://' || true)

    cross_check_ok=1
    if [ -z "$local_release_sha" ] || [ -z "$cask_sha" ] || [ -z "$gh_release_sha" ]; then
        # "Could not read" is not a benign outcome: it is precisely the state in
        # which divergence is invisible. Pre-fix this only suppressed a ✓ and the
        # release still exited 0.
        release_fail "could not read all three SHAs (release.json=$local_release_sha cask=$cask_sha gh=$gh_release_sha) — verify by hand before announcing"
        cross_check_ok=0
    elif [ "$local_release_sha" != "$cask_sha" ] || [ "$cask_sha" != "$gh_release_sha" ]; then
        echo "      release.json:      $local_release_sha" >&2
        echo "      Casks/maccrab.rb:  $cask_sha" >&2
        echo "      GH release asset:  $gh_release_sha" >&2
        release_fail "SHA MISMATCH — the published artifact is internally inconsistent; users will fail integrity verification against at least one of the three. Republish the lagging file with the correct SHA."
        cross_check_ok=0
    fi
    if [ "$cross_check_ok" = "1" ]; then
        echo "  ✓ release.json, Casks/maccrab.rb, and GitHub release all agree on SHA ${local_release_sha:0:16}..."
    fi

    # Step 6d: Publish the validated cask to the dedicated, append-only tap
    # repo (peterhanily/homebrew-maccrab) via the GitHub Contents API. New
    # users install with the one-liner
    #   brew install --cask peterhanily/maccrab/maccrab
    # which auto-taps that repo. Contents-API publishing is forward-only (one
    # clean commit, never a force-push), so `brew update` always fast-forwards
    # — unlike the old app-repo-as-tap, whose rewritten history poisoned every
    # existing clone with rebase conflicts. Token needs write on the tap repo.
    echo ""
    echo "Step 6d: Publishing cask to homebrew-maccrab tap..."
    if TAP_REPO_TOKEN="${TAP_REPO_TOKEN:-${GH_TOKEN:-$SITE_REPO_TOKEN}}" \
            "$SCRIPT_DIR/publish-cask.sh"; then
        echo "  ✓ Cask published; 'brew install --cask peterhanily/maccrab/maccrab' serves v$VERSION"
    else
        echo "  ! Cask publish failed — set TAP_REPO_TOKEN (PAT with contents:write on peterhanily/homebrew-maccrab) then run 'scripts/publish-cask.sh' manually" >&2
    fi
else
    echo ""
    echo "  Step 6/6: Skipping appcast publish."
    if [ -z "${SITE_REPO_TOKEN:-}" ]; then
        echo "  → SITE_REPO_TOKEN env var not set. Existing users will NOT receive the update."
        echo "    To publish: SITE_REPO_TOKEN=<pat> scripts/publish-appcast-entry.sh \\"
        echo "                  --item <(scripts/generate-appcast-entry.sh --dmg $DMG_PATH --version $VERSION)"
        echo "    Also remember: SITE_REPO_TOKEN=<pat> scripts/publish-release-json.sh"
        echo "                  (so maccrab.com/release.json stops lagging the release)"
    fi
fi

echo ""
# The release is only "released" if every publish step landed. Pre-fix this
# banner printed unconditionally and the script exited 0 even when the appcast,
# release.json, the cross-source SHA check and the tap cask had all failed —
# so a half-published release looked identical to a good one.
if [ "$RELEASE_FAILURE_COUNT" -gt 0 ]; then
    echo "═══════════════════════════════════════"
    echo "  MacCrab v$VERSION — RELEASE INCOMPLETE"
    echo "═══════════════════════════════════════"
    echo ""
    echo "  The DMG was built and uploaded (.build/MacCrab-v$VERSION.dmg) but"
    echo "  $RELEASE_FAILURE_COUNT publish step(s) did not land. Users are NOT fully served:"
    printf '%s' "$RELEASE_FAILURES"
    echo ""
    echo "  Fix each item above, re-run the named script, then re-verify:"
    echo "    curl -s https://maccrab.com/release.json"
    echo "    curl -s https://maccrab.com/appcast.xml | grep sparkle:version"
    exit 1
fi
echo "═══════════════════════════════════════"
echo "  MacCrab v$VERSION Released!"
echo "═══════════════════════════════════════"
echo ""
echo "  DMG: .build/MacCrab-v$VERSION.dmg"
echo ""
echo "  Users can install with:"
echo "    brew install --cask peterhanily/maccrab/maccrab"
echo ""
