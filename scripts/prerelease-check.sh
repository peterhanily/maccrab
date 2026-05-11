#!/bin/bash
# prerelease-check.sh — Verify release-relevant files are in sync before
# building / signing / publishing. Exits non-zero on hard errors; warnings
# are printed but don't block. Run automatically by release.sh; can also
# be run manually with:
#
#   scripts/prerelease-check.sh 1.3.12
#
# Hard errors (blocking):
#   - Version mismatch across project.yml / both plists / README badge
#   - Missing CHANGELOG.md section for this version
#   - Missing or stub RELEASE_NOTES/v{VERSION}.md
#   - Rules fail to compile
#
# Warnings (printed, non-blocking):
#   - README or site stat counts drift from actual test / rule counts
#   - Site repo out of sync with the new version
#   - Non-English locales below 50% key coverage
#   - String(localized: "key", ...) calls where `key` has no entry in
#     en.lproj/Localizable.strings
#
# Always run from the repo root.

set -uo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>" >&2
    echo "Example: $0 1.3.12" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

# Site repo location is conventional but not checked in. Allow override.
SITE_REPO_PATH="${SITE_REPO_PATH:-}"

# ---------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------

BOLD=$(tput bold 2>/dev/null || true)
DIM=$(tput dim 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GREEN=$(tput setaf 2 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
CYAN=$(tput setaf 6 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

ERRORS=0
WARNINGS=0

err()  { echo "${RED}✗${RESET} $*" >&2; ERRORS=$((ERRORS+1)); }
warn() { echo "${YELLOW}!${RESET} $*"; WARNINGS=$((WARNINGS+1)); }
ok()   { echo "${GREEN}✓${RESET} $*"; }
info() { echo "${CYAN}→${RESET} $*"; }
section() { echo; echo "${BOLD}── $* ──${RESET}"; }

# ---------------------------------------------------------------------
# 1. Version sync
# ---------------------------------------------------------------------

section "Version sync"

# Xcode/project.yml — should have two matching CFBundleVersion entries
# `grep -c` exits 1 when count is 0, so the prior `|| echo 0` form
# captured BOTH grep's `0` output AND the fallback `0`, yielding a
# two-line value `"0\n0"` that bash's `[[ -lt ]]` could not parse —
# the syntax error caused `[[` to exit non-zero, the `else` branch
# ran, and a stale project.yml shipped green. Capture grep's stdout
# alone and reset to 0 only if grep itself failed.
PROJECT_YML_COUNT=$(grep -c "CFBundleVersion: \"$VERSION\"" Xcode/project.yml 2>/dev/null) || PROJECT_YML_COUNT=0
if [[ "$PROJECT_YML_COUNT" -lt 2 ]]; then
    err "Xcode/project.yml: CFBundleVersion not set to $VERSION in both targets (found $PROJECT_YML_COUNT)"
else
    ok "Xcode/project.yml → $VERSION (app + sysext)"
fi

# v1.6.18: also validate CFBundleShortVersionString. The pre-v1.6.18
# check covered CFBundleVersion only, so the short version drifted to
# 1.6.4 across 13 releases until a manual audit caught it.
PROJECT_YML_SHORT_COUNT=$(grep -c "CFBundleShortVersionString: \"$VERSION\"" Xcode/project.yml 2>/dev/null) || PROJECT_YML_SHORT_COUNT=0
if [[ "$PROJECT_YML_SHORT_COUNT" -lt 2 ]]; then
    err "Xcode/project.yml: CFBundleShortVersionString not set to $VERSION in both targets (found $PROJECT_YML_SHORT_COUNT)"
else
    ok "Xcode/project.yml → CFBundleShortVersionString $VERSION (app + sysext)"
fi

# Info.plist — must contain the version string somewhere
for plist in Xcode/Resources/MacCrabApp-Info.plist Xcode/Resources/MacCrabAgent-Info.plist; do
    if grep -q "<string>$VERSION</string>" "$plist" 2>/dev/null; then
        ok "$plist → $VERSION"
    else
        err "$plist does not contain <string>$VERSION</string>"
    fi
done

# README.md badge
if grep -q "version-${VERSION//./\\.}-" README.md 2>/dev/null; then
    ok "README.md version badge → $VERSION"
else
    err "README.md version badge doesn't reference $VERSION"
fi

# MacCrabVersion.fallback parity. Bundle-less binaries (maccrabctl
# CLI, dev `swift run maccrabd`) report this constant when no
# CFBundleShortVersionString is reachable. Drift here means OCSF
# records, fleet telemetry, daemon banners, and version dialogs all
# claim a different version than the shipped DMG. Audit F49.
FALLBACK_VER=$(grep -E '^[[:space:]]*public static let fallback:' \
    Sources/MacCrabCore/MacCrabVersion.swift 2>/dev/null \
    | head -1 \
    | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$FALLBACK_VER" ]; then
    err "MacCrabVersion.fallback: couldn't parse the constant"
elif [ "$FALLBACK_VER" != "$VERSION" ]; then
    err "MacCrabVersion.fallback=\"$FALLBACK_VER\" but expected \"$VERSION\""
else
    ok "Sources/MacCrabCore/MacCrabVersion.swift → fallback $VERSION"
fi

# ---------------------------------------------------------------------
# 2. CHANGELOG + RELEASE_NOTES
# ---------------------------------------------------------------------

section "Release notes"

if grep -q "^## \[$VERSION\] — " CHANGELOG.md 2>/dev/null; then
    ok "CHANGELOG.md → has [$VERSION] section"
else
    err "CHANGELOG.md is missing a ## [$VERSION] — YYYY-MM-DD header"
fi

NOTES_FILE="RELEASE_NOTES/v${VERSION}.md"
if [[ ! -f "$NOTES_FILE" ]]; then
    err "$NOTES_FILE does not exist (user-facing release notes are required)"
else
    # Rough stub detector: fewer than 10 non-blank lines is a stub.
    CONTENT_LINES=$(grep -cE '\S' "$NOTES_FILE")
    if [[ "$CONTENT_LINES" -lt 10 ]]; then
        err "$NOTES_FILE exists but has only $CONTENT_LINES lines of content (looks like a stub)"
    else
        ok "$NOTES_FILE → $CONTENT_LINES lines"
    fi
fi

# ---------------------------------------------------------------------
# 3. Stats sync
# ---------------------------------------------------------------------

section "Stats sync"

ACTUAL_RULES=$(find Rules -name "*.yml" -type f 2>/dev/null | wc -l | tr -d ' ')
# Badge URL is `.../detection%20rules-<N>-orange` — pull the number that
# sits between the second `-` and the colour name. Naïve `[0-9]+` would
# also match the `20` in `%20`.
README_RULES=$(grep -oE 'detection%20rules-[0-9]+-[a-z]+' README.md \
    | sed -E 's/detection%20rules-([0-9]+)-.*/\1/' | head -1)
if [[ -z "$README_RULES" ]]; then
    warn "README.md: couldn't parse rules badge"
elif [[ "$README_RULES" != "$ACTUAL_RULES" ]]; then
    warn "README.md rules badge = $README_RULES, actual = $ACTUAL_RULES"
else
    ok "README.md rules badge → $ACTUAL_RULES"
fi

# Tests badge has the same `%20passing` trap.
README_TESTS=$(grep -oE 'tests-[0-9]+%20passing' README.md \
    | sed -E 's/tests-([0-9]+)%20passing/\1/' | head -1)
if [[ -z "$README_TESTS" ]]; then
    warn "README.md: couldn't parse tests badge"
else
    info "README.md tests badge = $README_TESTS (run \`swift test\` to validate)"
fi

# Site
if [[ -d "$SITE_REPO_PATH" && -f "$SITE_REPO_PATH/index.html" ]]; then
    SITE_HTML="$SITE_REPO_PATH/index.html"
    if grep -q "\"softwareVersion\": \"$VERSION\"" "$SITE_HTML"; then
        ok "site: softwareVersion → $VERSION"
    else
        warn "site: softwareVersion not $VERSION"
    fi
    if grep -q "v$VERSION</span>" "$SITE_HTML"; then
        ok "site: hero pill → v$VERSION"
    else
        warn "site: hero pill not v$VERSION"
    fi
    if grep -q "What ships in v$VERSION" "$SITE_HTML"; then
        ok "site: 'What ships' heading → v$VERSION"
    else
        warn "site: 'What ships' heading not v$VERSION"
    fi
else
    info "site repo not at $SITE_REPO_PATH — skipping site checks"
fi

# ---------------------------------------------------------------------
# 4. Localization coverage
# ---------------------------------------------------------------------

section "Localization coverage"

EN_STRINGS="Sources/MacCrabApp/Resources/en.lproj/Localizable.strings"
if [[ ! -f "$EN_STRINGS" ]]; then
    err "$EN_STRINGS missing"
else
    # Collect every "key" mentioned in String(localized: "...") in Swift source.
    USED_KEYS=$(grep -rhoE 'String\(localized: "[^"]+"' Sources/MacCrabApp/ 2>/dev/null \
        | sed -E 's/.*"([^"]+)"/\1/' \
        | sort -u)
    # Collect every key defined in en.lproj.
    EN_KEYS=$(grep -oE '^"[^"]+"' "$EN_STRINGS" 2>/dev/null \
        | tr -d '"' \
        | sort -u)

    USED_COUNT=$(echo "$USED_KEYS" | grep -c '^' || echo 0)
    EN_COUNT=$(echo "$EN_KEYS" | grep -c '^' || echo 0)
    info "Swift uses $USED_COUNT localized keys; en.lproj defines $EN_COUNT"

    MISSING_IN_EN=$(comm -23 <(echo "$USED_KEYS") <(echo "$EN_KEYS") | grep -cE '\S' || echo 0)
    if [[ "$MISSING_IN_EN" -gt 0 ]]; then
        warn "$MISSING_IN_EN key(s) used in Swift have no en.lproj entry — defaultValue will be used but adding explicit keys helps translators"
        comm -23 <(echo "$USED_KEYS") <(echo "$EN_KEYS") | head -5 | while read -r k; do
            echo "    $DIM- $k$RESET"
        done
    else
        ok "Every localized key in Swift has an en.lproj entry"
    fi

    # Per-locale coverage
    for lproj in Sources/MacCrabApp/Resources/*.lproj; do
        [[ -d "$lproj" ]] || continue
        LOCALE=$(basename "$lproj" .lproj)
        [[ "$LOCALE" == "en" ]] && continue
        LOCALE_STRINGS="$lproj/Localizable.strings"
        [[ -f "$LOCALE_STRINGS" ]] || continue
        LOCALE_KEYS=$(grep -oE '^"[^"]+"' "$LOCALE_STRINGS" | tr -d '"' | sort -u)
        LOCALE_COUNT=$(echo "$LOCALE_KEYS" | grep -c '^' || echo 0)
        if [[ "$EN_COUNT" -gt 0 ]]; then
            PERCENT=$(( 100 * LOCALE_COUNT / EN_COUNT ))
            if [[ "$PERCENT" -lt 50 ]]; then
                warn "$LOCALE: $LOCALE_COUNT/$EN_COUNT keys ($PERCENT%) — below 50%"
            elif [[ "$PERCENT" -lt 100 ]]; then
                info "$LOCALE: $LOCALE_COUNT/$EN_COUNT keys ($PERCENT%)"
            else
                ok "$LOCALE: $LOCALE_COUNT/$EN_COUNT keys (100%)"
            fi
        fi
    done
fi

# ---------------------------------------------------------------------
# 5. Rules
# ---------------------------------------------------------------------

section "Rules"

COMPILE_OUT=$(python3 Compiler/compile_rules.py \
    --input-dir Rules/ --output-dir .build/compiled_rules 2>&1)
COMPILE_RC=$?
# Output is right-aligned `Rules skipped:     0` — match any whitespace
# run so the check doesn't break if the padding changes.
if [[ "$COMPILE_RC" -eq 0 ]] && echo "$COMPILE_OUT" | grep -qE 'Rules skipped:[[:space:]]+0\b'; then
    ok "All rules compile, 0 skipped"
else
    err "Compiler reported failures or skipped rules:"
    echo "$COMPILE_OUT" | tail -10 | sed 's/^/    /'
fi

# ---------------------------------------------------------------------
# 6. Supply chain
# ---------------------------------------------------------------------

section "Supply chain"

if [[ -f Package.resolved ]]; then
    if grep -qE '^!Package.resolved$|^Package.resolved$' .gitignore 2>/dev/null; then
        warn ".gitignore excludes Package.resolved — SPM pins won't be reproducible across envs"
    else
        ok "Package.resolved committed and tracked"
    fi
else
    err "Package.resolved missing — run \`swift package resolve\` and commit"
fi

if grep -qE '\.package\(url:.*Sparkle.*exact:' Package.swift; then
    ok "Sparkle pinned .exact(...)"
else
    warn "Sparkle not .exact(...) — supply chain hardening regressed"
fi

# ---------------------------------------------------------------------
# 7. Manifest equality (v1.6.19)
# ---------------------------------------------------------------------
# Three duplicated sources of truth that the release flow has burned us
# on before. Each pair MUST match exactly; mismatches were the root
# cause of the v1.6.13 stale-Casks incident, the v1.6.18 short-version
# drift, and would brick auto-update if the SUPublicEDKey ever drifts
# (no rollback path: Sparkle clients verify against the value baked
# into the installed bundle).

section "Manifest equality"

# Cask version equality: both the homebrew/ doc copy and the Casks/
# canonical (what `brew` actually reads) must equal $VERSION.
CASKS_VER=$(grep -E '^[[:space:]]*version[[:space:]]+"' Casks/maccrab.rb 2>/dev/null \
    | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
BREW_VER=$(grep -E '^[[:space:]]*version[[:space:]]+"' homebrew/maccrab.rb 2>/dev/null \
    | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
if [[ -z "$CASKS_VER" ]]; then
    err "Casks/maccrab.rb: couldn't parse version field"
elif [[ "$CASKS_VER" != "$VERSION" ]]; then
    err "Casks/maccrab.rb version=\"$CASKS_VER\" but expected \"$VERSION\""
else
    ok "Casks/maccrab.rb → $CASKS_VER"
fi
if [[ -z "$BREW_VER" ]]; then
    err "homebrew/maccrab.rb: couldn't parse version field"
elif [[ "$BREW_VER" != "$VERSION" ]]; then
    err "homebrew/maccrab.rb version=\"$BREW_VER\" but expected \"$VERSION\" (Casks/ and homebrew/ drift caused 9 stale releases pre-v1.6.13)"
else
    ok "homebrew/maccrab.rb → $BREW_VER"
fi

# Appcast URL equality: project.yml and Info.plist must agree.
# Anchor on the start of line so a YAML comment mentioning "SUFeedURL:"
# can't match (project.yml's real line starts with leading spaces +
# "SUFeedURL:"). For Info.plist anchor on the literal XML key form
# `<key>SUFeedURL</key>` so a comment mentioning the name is ignored.
APPCAST_YML=$(grep -E '^[[:space:]]*SUFeedURL:' Xcode/project.yml 2>/dev/null \
    | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
APPCAST_PLIST=$(awk '/<key>SUFeedURL<\/key>/{getline; print}' Xcode/Resources/MacCrabApp-Info.plist 2>/dev/null \
    | sed -E 's/.*<string>([^<]+)<.*/\1/' | tr -d '[:space:]')
if [[ -z "$APPCAST_YML" || -z "$APPCAST_PLIST" ]]; then
    err "SUFeedURL missing from project.yml ($APPCAST_YML) or Info.plist ($APPCAST_PLIST)"
elif [[ "$APPCAST_YML" != "$APPCAST_PLIST" ]]; then
    err "Sparkle appcast URL drift: project.yml=\"$APPCAST_YML\" vs Info.plist=\"$APPCAST_PLIST\""
else
    ok "Sparkle appcast URL → $APPCAST_YML (project.yml matches Info.plist)"
fi

# Sparkle EdDSA public key equality. Drift here would brick auto-update
# for every existing user with no rollback path — bumping severity to
# err over a warning even though it's not a per-version field.
EDKEY_YML=$(grep -E '^[[:space:]]*SUPublicEDKey:' Xcode/project.yml 2>/dev/null \
    | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
EDKEY_PLIST=$(awk '/<key>SUPublicEDKey<\/key>/{getline; print}' Xcode/Resources/MacCrabApp-Info.plist 2>/dev/null \
    | sed -E 's/.*<string>([^<]+)<.*/\1/' | tr -d '[:space:]')
if [[ -z "$EDKEY_YML" || -z "$EDKEY_PLIST" ]]; then
    err "SUPublicEDKey missing from project.yml or Info.plist"
elif [[ "$EDKEY_YML" != "$EDKEY_PLIST" ]]; then
    err "Sparkle public key drift: project.yml=\"${EDKEY_YML:0:8}…\" vs Info.plist=\"${EDKEY_PLIST:0:8}…\" — auto-update would break for installed users"
else
    ok "Sparkle EdDSA public key → ${EDKEY_YML:0:8}… (project.yml matches Info.plist)"
fi

# Bundle identifiers: project.yml is canonical, Info.plists must match.
# project.yml has app + sysext as separate target stanzas, so we extract
# both occurrences in declaration order.
BUNDLE_IDS_YML=$(grep -E '^[[:space:]]*CFBundleIdentifier:' Xcode/project.yml 2>/dev/null \
    | sed -E 's/.*CFBundleIdentifier:[[:space:]]+(.+)/\1/' | tr -d '"\r')
APP_BID_YML=$(echo "$BUNDLE_IDS_YML" | sed -n '1p' | tr -d ' \t')
SYSEXT_BID_YML=$(echo "$BUNDLE_IDS_YML" | sed -n '2p' | tr -d ' \t')
APP_BID_PLIST=$(awk '/<key>CFBundleIdentifier<\/key>/{getline; print}' Xcode/Resources/MacCrabApp-Info.plist 2>/dev/null \
    | sed -E 's/.*<string>([^<]+)<.*/\1/' | tr -d '[:space:]')
SYSEXT_BID_PLIST=$(awk '/<key>CFBundleIdentifier<\/key>/{getline; print}' Xcode/Resources/MacCrabAgent-Info.plist 2>/dev/null \
    | sed -E 's/.*<string>([^<]+)<.*/\1/' | tr -d '[:space:]')
if [[ -z "$APP_BID_YML" || -z "$APP_BID_PLIST" ]]; then
    err "App CFBundleIdentifier missing from project.yml ($APP_BID_YML) or Info.plist ($APP_BID_PLIST)"
elif [[ "$APP_BID_YML" != "$APP_BID_PLIST" ]]; then
    err "App CFBundleIdentifier drift: project.yml=$APP_BID_YML vs Info.plist=$APP_BID_PLIST"
else
    ok "App CFBundleIdentifier → $APP_BID_YML (project.yml matches Info.plist)"
fi
if [[ -z "$SYSEXT_BID_YML" || -z "$SYSEXT_BID_PLIST" ]]; then
    err "Sysext CFBundleIdentifier missing from project.yml ($SYSEXT_BID_YML) or Info.plist ($SYSEXT_BID_PLIST)"
elif [[ "$SYSEXT_BID_YML" != "$SYSEXT_BID_PLIST" ]]; then
    err "Sysext CFBundleIdentifier drift: project.yml=$SYSEXT_BID_YML vs Info.plist=$SYSEXT_BID_PLIST"
else
    ok "Sysext CFBundleIdentifier → $SYSEXT_BID_YML (project.yml matches Info.plist)"
fi

# Apple Developer Team ID. project.yml has the canonical value (twice —
# once per target). Verify they agree, then verify the Casks/homebrew
# uninstall stanzas reference the same ID. Drift would invalidate the
# uninstall flow for users running an updated team's signed app.
TEAM_IDS_YML=$(grep -E '^[[:space:]]*DEVELOPMENT_TEAM:' Xcode/project.yml 2>/dev/null \
    | awk '{print $2}' | tr -d '"' | sort -u)
TEAM_ID_COUNT=$(echo "$TEAM_IDS_YML" | grep -c '^' || echo 0)
if [[ "$TEAM_ID_COUNT" -ne 1 ]]; then
    err "Xcode/project.yml: DEVELOPMENT_TEAM disagrees across targets ($TEAM_ID_COUNT distinct values: $TEAM_IDS_YML)"
else
    TEAM_ID="$TEAM_IDS_YML"
    ok "Apple Developer Team ID → $TEAM_ID (project.yml app + sysext agree)"
    # Cask uninstall stanzas reference the team ID. If your team ID
    # rotates and one of these is forgotten, brew uninstall fails for
    # users still on the old build.
    for cask in Casks/maccrab.rb homebrew/maccrab.rb; do
        if [[ -f "$cask" ]]; then
            if grep -q "$TEAM_ID" "$cask"; then
                ok "$cask references $TEAM_ID"
            else
                err "$cask does not reference DEVELOPMENT_TEAM=$TEAM_ID"
            fi
        fi
    done
fi

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------

section "Summary"

if [[ "$ERRORS" -gt 0 ]]; then
    echo "${RED}${BOLD}FAILED${RESET} — $ERRORS error(s), $WARNINGS warning(s)"
    exit 1
fi

if [[ "$WARNINGS" -gt 0 ]]; then
    echo "${YELLOW}${BOLD}PASSED${RESET} (with $WARNINGS warning(s))"
else
    echo "${GREEN}${BOLD}PASSED${RESET}"
fi
exit 0
