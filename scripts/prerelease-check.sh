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
PROJECT_YML_COUNT=$(grep -c "CFBundleVersion: \"$VERSION\"" Xcode/project.yml 2>/dev/null || echo 0)
if [[ "$PROJECT_YML_COUNT" -lt 2 ]]; then
    err "Xcode/project.yml: CFBundleVersion not set to $VERSION in both targets (found $PROJECT_YML_COUNT)"
else
    ok "Xcode/project.yml → $VERSION (app + sysext)"
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
