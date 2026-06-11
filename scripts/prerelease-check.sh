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
    echo "         $0 1.13.0-rc.1   # release-candidate; source files still carry 1.13.0" >&2
    exit 2
fi

# Mac Context Plugin Platform RC handling (v1.13a+):
#
# Release-candidate versions look like "1.13.0-rc.1". Source files
# carrying SemVer-only fields (Info.plists, project.yml, MacCrabVersion
# fallback, cask versions) can't hold the -rc suffix — Apple
# constrains CFBundleShortVersionString to MAJOR.MINOR.PATCH; the cask
# would publish ahead of the GA build. Only release.json + the git
# tag carry the full RC string.
#
# VERSION_SEMVER strips the -rc suffix for the source-tree parity
# checks; VERSION carries the full string for release.json / DMG
# filename / tag checks. The two diverge only when shipping an RC.
VERSION_SEMVER="${VERSION%%-rc.*}"
VERSION_IS_RC=0
if [[ "$VERSION_SEMVER" != "$VERSION" ]]; then
    VERSION_IS_RC=1
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
PROJECT_YML_COUNT=$(grep -c "CFBundleVersion: \"$VERSION_SEMVER\"" Xcode/project.yml 2>/dev/null) || PROJECT_YML_COUNT=0
if [[ "$PROJECT_YML_COUNT" -lt 2 ]]; then
    err "Xcode/project.yml: CFBundleVersion not set to $VERSION_SEMVER in both targets (found $PROJECT_YML_COUNT)"
else
    ok "Xcode/project.yml → $VERSION_SEMVER (app + sysext)"
fi

# v1.6.18: also validate CFBundleShortVersionString. The pre-v1.6.18
# check covered CFBundleVersion only, so the short version drifted to
# 1.6.4 across 13 releases until a manual audit caught it.
PROJECT_YML_SHORT_COUNT=$(grep -c "CFBundleShortVersionString: \"$VERSION_SEMVER\"" Xcode/project.yml 2>/dev/null) || PROJECT_YML_SHORT_COUNT=0
if [[ "$PROJECT_YML_SHORT_COUNT" -lt 2 ]]; then
    err "Xcode/project.yml: CFBundleShortVersionString not set to $VERSION_SEMVER in both targets (found $PROJECT_YML_SHORT_COUNT)"
else
    ok "Xcode/project.yml → CFBundleShortVersionString $VERSION_SEMVER (app + sysext)"
fi

# Info.plist — must contain the version string somewhere
for plist in Xcode/Resources/MacCrabApp-Info.plist Xcode/Resources/MacCrabAgent-Info.plist; do
    if grep -q "<string>$VERSION_SEMVER</string>" "$plist" 2>/dev/null; then
        ok "$plist → $VERSION_SEMVER"
    else
        err "$plist does not contain <string>$VERSION_SEMVER</string>"
    fi
done

# README.md badge
if grep -q "version-${VERSION_SEMVER//./\\.}-" README.md 2>/dev/null; then
    ok "README.md version badge → $VERSION_SEMVER"
else
    err "README.md version badge doesn't reference $VERSION_SEMVER"
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
elif [ "$FALLBACK_VER" != "$VERSION_SEMVER" ]; then
    err "MacCrabVersion.fallback=\"$FALLBACK_VER\" but expected \"$VERSION_SEMVER\""
else
    ok "Sources/MacCrabCore/MacCrabVersion.swift → fallback $VERSION_SEMVER"
fi

# ---------------------------------------------------------------------
# 2. CHANGELOG + RELEASE_NOTES
# ---------------------------------------------------------------------

section "Release notes"

if grep -q "^## \[$VERSION\] — " CHANGELOG.md 2>/dev/null; then
    ok "CHANGELOG.md → has [$VERSION] section"
elif [[ "$VERSION_IS_RC" == "1" ]]; then
    # RCs don't require a CHANGELOG entry. The GA release that
    # follows the RC arc will carry the cumulative entry. Warn so
    # the omission is visible but not blocking.
    warn "CHANGELOG.md has no [$VERSION] section — acceptable for RCs; the GA release will carry the entry"
else
    err "CHANGELOG.md is missing a ## [$VERSION] — YYYY-MM-DD header"
fi

NOTES_FILE="RELEASE_NOTES/v${VERSION}.md"
if [[ ! -f "$NOTES_FILE" ]]; then
    if [[ "$VERSION_IS_RC" == "1" ]]; then
        warn "$NOTES_FILE does not exist — acceptable for RCs; full release notes ship with the GA"
    else
        err "$NOTES_FILE does not exist (user-facing release notes are required)"
    fi
else
    # Rough stub detector: fewer than 10 non-blank lines is a stub.
    CONTENT_LINES=$(grep -cE '\S' "$NOTES_FILE")
    if [[ "$CONTENT_LINES" -lt 10 ]]; then
        if [[ "$VERSION_IS_RC" == "1" ]]; then
            warn "$NOTES_FILE has only $CONTENT_LINES lines — acceptable for RCs"
        else
            err "$NOTES_FILE exists but has only $CONTENT_LINES lines of content (looks like a stub)"
        fi
    else
        ok "$NOTES_FILE → $CONTENT_LINES lines"
    fi
fi

# ---------------------------------------------------------------------
# 3. Stats sync
# ---------------------------------------------------------------------

section "Stats sync"

# The rules badge encodes all three classes: `rules-<single>%20%2B%20<seq>%20seq
# %20%2B%20<graph>%20graph-<colour>`. Verify each against the canonical counts
# (coverage_matrix.py is the single source of truth — same one check-counts uses).
CANON=$(python3 scripts/coverage_matrix.py --counts Rules 2>/dev/null)
C_SINGLE=$(echo "$CANON" | sed -E 's/.*single=([0-9]+).*/\1/')
C_SEQ=$(echo "$CANON" | sed -E 's/.*sequence=([0-9]+).*/\1/')
C_GRAPH=$(echo "$CANON" | sed -E 's/.*graph=([0-9]+).*/\1/')
BADGE=$(grep -oE 'badge/rules-[0-9]+%20%2B%20[0-9]+%20seq%20%2B%20[0-9]+%20graph' README.md | head -1)
if [[ -z "$BADGE" ]]; then
    warn "README.md: couldn't parse rules badge"
else
    B_SINGLE=$(echo "$BADGE" | sed -E 's#badge/rules-([0-9]+)%20.*#\1#')
    B_SEQ=$(echo "$BADGE" | sed -E 's#.*%2B%20([0-9]+)%20seq.*#\1#')
    B_GRAPH=$(echo "$BADGE" | sed -E 's#.*%2B%20([0-9]+)%20graph#\1#')
    if [[ "$B_SINGLE" == "$C_SINGLE" && "$B_SEQ" == "$C_SEQ" && "$B_GRAPH" == "$C_GRAPH" ]]; then
        ok "README.md rules badge → $B_SINGLE + $B_SEQ seq + $B_GRAPH graph"
    else
        warn "README.md rules badge = ${B_SINGLE}+${B_SEQ}+${B_GRAPH}, canonical = ${C_SINGLE}+${C_SEQ}+${C_GRAPH}"
    fi
fi

# Tests badge has the same `%20passing` trap.
README_TESTS=$(grep -oE 'tests-[0-9]+%20passing' README.md \
    | sed -E 's/tests-([0-9]+)%20passing/\1/' | head -1)
if [[ -z "$README_TESTS" ]]; then
    warn "README.md: couldn't parse tests badge"
else
    info "README.md tests badge = $README_TESTS (run \`swift test\` to validate)"
fi

# v1.19.0 (S7-7): release.json must be the single source of truth for the
# public rule total AND its breakdown. Assert the rules total + each class +
# the built-in count all agree with the canonical compiler counts and
# BuiltinRuleCatalog.swift. Hard error — a drift here ships a contradictory
# "483" to the website / app card / About string.
C_TOTAL=$(echo "$CANON" | sed -E 's/.*total=([0-9]+).*/\1/')
RJSON="$REPO_ROOT/release.json"
if [[ -f "$RJSON" ]]; then
    rj() { grep -oE "\"$1\"[[:space:]]*:[[:space:]]*[0-9]+" "$RJSON" | grep -oE '[0-9]+$' | head -1; }
    RJ_RULES=$(rj rules); RJ_SINGLE=$(rj rules_single)
    RJ_SEQ=$(rj rules_sequence); RJ_GRAPH=$(rj rules_graph); RJ_BUILTINS=$(rj builtins)
    if [[ "$RJ_RULES" == "$C_TOTAL" && "$RJ_SINGLE" == "$C_SINGLE" \
          && "$RJ_SEQ" == "$C_SEQ" && "$RJ_GRAPH" == "$C_GRAPH" ]]; then
        ok "release.json rules → $RJ_RULES (single $RJ_SINGLE + seq $RJ_SEQ + graph $RJ_GRAPH)"
    else
        err "release.json rules drift: total=$RJ_RULES single=$RJ_SINGLE seq=$RJ_SEQ graph=$RJ_GRAPH, canonical=$C_TOTAL/$C_SINGLE/$C_SEQ/$C_GRAPH"
    fi
    # release.json total must equal the sum of its own breakdown.
    if [[ -n "$RJ_SINGLE" && -n "$RJ_SEQ" && -n "$RJ_GRAPH" ]] \
       && [[ "$RJ_RULES" -ne $((RJ_SINGLE + RJ_SEQ + RJ_GRAPH)) ]]; then
        err "release.json: rules ($RJ_RULES) != single+seq+graph ($((RJ_SINGLE + RJ_SEQ + RJ_GRAPH)))"
    fi
    CAT_BUILTINS=$(grep -c '\.init("maccrab\.' "$REPO_ROOT/Sources/MacCrabCore/Detection/BuiltinRuleCatalog.swift")
    if [[ "$RJ_BUILTINS" == "$CAT_BUILTINS" ]]; then
        ok "release.json builtins → $RJ_BUILTINS (matches BuiltinRuleCatalog)"
    else
        err "release.json builtins=$RJ_BUILTINS, BuiltinRuleCatalog.all=$CAT_BUILTINS"
    fi
else
    warn "release.json not found — skipping rule-breakdown sync check"
fi

# The app's About string (settings.aboutStats) must carry the same rule
# total. Option A: it states the public "483 detection rules", NOT the
# Sigma+built-in sum. Assert the en.lproj value and the Swift defaultValue
# both reference the canonical total.
ABOUT_EN=$(grep -E '"settings\.aboutStats"' "$REPO_ROOT/Sources/MacCrabApp/Resources/en.lproj/Localizable.strings" | head -1)
if echo "$ABOUT_EN" | grep -q "$C_TOTAL"; then
    ok "en.lproj settings.aboutStats → states $C_TOTAL rules"
else
    err "en.lproj settings.aboutStats does not reference the canonical total $C_TOTAL: $ABOUT_EN"
fi
ABOUT_DEFAULT=$(grep -E 'settings\.aboutStats".*defaultValue:' "$REPO_ROOT/Sources/MacCrabApp/Views/SettingsView.swift" | head -1)
if echo "$ABOUT_DEFAULT" | grep -q "$C_TOTAL"; then
    ok "SettingsView aboutStats defaultValue → states $C_TOTAL rules"
else
    err "SettingsView settings.aboutStats defaultValue does not reference $C_TOTAL: $ABOUT_DEFAULT"
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

    # NB: grep -c prints "0" AND exits 1 on zero matches — `|| echo 0` would
    # append a second line ("0\n0") and break numeric comparisons (v1.18.1,
    # first surfaced the day the missing-key list actually reached zero).
    USED_COUNT=$(echo "$USED_KEYS" | grep -c '^' || true)
    EN_COUNT=$(echo "$EN_KEYS" | grep -c '^' || true)
    info "Swift uses $USED_COUNT localized keys; en.lproj defines $EN_COUNT"

    MISSING_IN_EN=$(comm -23 <(echo "$USED_KEYS") <(echo "$EN_KEYS") | grep -cE '\S' || true)
    if [[ "$MISSING_IN_EN" -gt 0 ]]; then
        warn "$MISSING_IN_EN key(s) used in Swift have no en.lproj entry — defaultValue will be used but adding explicit keys helps translators"
        comm -23 <(echo "$USED_KEYS") <(echo "$EN_KEYS") | head -5 | while read -r k; do
            echo "    $DIM- $k$RESET"
        done
    else
        ok "Every localized key in Swift has an en.lproj entry"
    fi

    # Per-locale coverage — key count AND value-divergence. A bundle can carry
    # 100% of the keys while most VALUES are byte-identical English (i.e. not
    # actually translated); the old key-count ratio reported that as 100% and
    # hid it (audit). Report the translated-value %, which is the real signal.
    for lproj in Sources/MacCrabApp/Resources/*.lproj; do
        [[ -d "$lproj" ]] || continue
        LOCALE=$(basename "$lproj" .lproj)
        [[ "$LOCALE" == "en" ]] && continue
        LOCALE_STRINGS="$lproj/Localizable.strings"
        [[ -f "$LOCALE_STRINGS" ]] || continue
        read -r LOCALE_COUNT TRANSLATED_PCT < <(python3 - "$EN_STRINGS" "$LOCALE_STRINGS" <<'PY'
import re, sys
def parse(p):
    d = {}
    for ln in open(p, encoding="utf-8", errors="replace"):
        m = re.match(r'\s*"((?:[^"\\]|\\.)*)"\s*=\s*"((?:[^"\\]|\\.)*)"\s*;', ln)
        if m: d[m.group(1)] = m.group(2)
    return d
en = parse(sys.argv[1]); loc = parse(sys.argv[2])
shared = [k for k in loc if k in en]
translated = sum(1 for k in shared if loc[k] != en[k])
pct = (100 * translated // len(en)) if en else 0
print(len(loc), pct)
PY
)
        if [[ "$EN_COUNT" -gt 0 ]]; then
            KEYPCT=$(( 100 * LOCALE_COUNT / EN_COUNT ))
            if [[ "$TRANSLATED_PCT" -lt 50 ]]; then
                warn "$LOCALE: $LOCALE_COUNT/$EN_COUNT keys (${KEYPCT}%) but only ${TRANSLATED_PCT}% translated — rest byte-identical English"
            elif [[ "$TRANSLATED_PCT" -lt 90 ]]; then
                info "$LOCALE: $LOCALE_COUNT/$EN_COUNT keys, ${TRANSLATED_PCT}% translated"
            else
                ok "$LOCALE: $LOCALE_COUNT/$EN_COUNT keys, ${TRANSLATED_PCT}% translated"
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
elif [[ "$VERSION_IS_RC" == "1" ]]; then
    # Casks stay on the previous GA during RC arcs — Sparkle and
    # Homebrew don't ship RCs to the public channel. The cask
    # version must NOT match VERSION_SEMVER (which would imply the
    # cask is the same as the in-progress source) — that's a sign
    # someone bumped the cask prematurely. Just report what's on
    # the cask; don't fail.
    info "Casks/maccrab.rb → $CASKS_VER (held; bumped at GA, not on RCs)"
elif [[ "$CASKS_VER" != "$VERSION_SEMVER" ]]; then
    err "Casks/maccrab.rb version=\"$CASKS_VER\" but expected \"$VERSION_SEMVER\""
else
    ok "Casks/maccrab.rb → $CASKS_VER"
fi
if [[ -z "$BREW_VER" ]]; then
    err "homebrew/maccrab.rb: couldn't parse version field"
elif [[ "$VERSION_IS_RC" == "1" ]]; then
    info "homebrew/maccrab.rb → $BREW_VER (held; bumped at GA, not on RCs)"
elif [[ "$BREW_VER" != "$VERSION_SEMVER" ]]; then
    err "homebrew/maccrab.rb version=\"$BREW_VER\" but expected \"$VERSION_SEMVER\" (Casks/ and homebrew/ drift caused 9 stale releases pre-v1.6.13)"
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
