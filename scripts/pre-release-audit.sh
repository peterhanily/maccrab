#!/bin/bash
# pre-release-audit.sh — enforce three architectural invariants that
# the v1.6.x release stream kept burning us on. Sister script to
# prerelease-check.sh: that one verifies manifest sync; this one
# verifies code structure.
#
# v1.6.19 institutional fix for the bug class the "wire-the-orphans"
# pattern names. Previously these audits were performed manually by a
# review-pass agent and the findings shipped one release later. Codifying
# them means a regression fails the next release pipeline run.
#
# Three passes:
#
#   PASS 1 — orphan audit
#     For every Settings @AppStorage that affects daemon behavior, grep
#     for a sync function that writes the value to disk. Missing sync =
#     orphan (the v1.6.12 maxDatabaseSizeMB / v1.6.18 webhook patterns).
#
#   PASS 2 — direct-insert audit
#     No code outside Sources/MacCrabCore/Detection/AlertSink.swift may
#     call alertStore.insert(...). Two audited exceptions in DaemonSetup
#     are documented inline. v1.6.19 single-sink invariant.
#
#   PASS 3 — duplicate-source audit
#     Every constant or path that lives in two files (Compiler-emitted
#     rule paths, default support dirs, daemon config keys) must appear
#     identically. Catches the v1.6.13 cask drift / v1.6.18 short-version
#     drift class but for source code rather than manifests.
#
# Hard errors block; warnings advise.
#
# Usage: scripts/pre-release-audit.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

BOLD=$(tput bold 2>/dev/null || true)
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
# PASS 1 — orphan audit (Settings @AppStorage → daemon consumer)
# ---------------------------------------------------------------------
# Each binding is a (storage-key, sync-function-name) pair. The sync
# function must exist in SettingsView; that's evidence the value
# reaches a file the daemon reads. Bindings that AREN'T daemon-relevant
# (UI-only preferences) are listed in IGNORE so they don't flag.

section "PASS 1 — Settings → daemon orphan audit"

SETTINGS_FILE="Sources/MacCrabApp/Views/SettingsView.swift"
if [[ ! -f "$SETTINGS_FILE" ]]; then
    err "$SETTINGS_FILE missing — can't audit"
else
    # Bindings that intentionally stay app-side (UI prefs, transient
    # state, OS-managed login items). Update when adding new ones.
    UI_ONLY_KEYS=(
        "alertNotifications"
        "minAlertSeverity"
        "pollIntervalSeconds"
        "launchAtLogin"
        "uiMode.storageKey"   # UIMode.storageKey constant
    )

    # Bindings that MUST round-trip to the daemon. Each maps to a sync
    # function that writes a JSON file the sysext reads.
    declare -a DAEMON_BINDINGS=(
        "retentionDays:syncStorageOverrides"
        "maxDatabaseSizeMB:syncStorageOverrides"
        "retentionWindowDays:syncStorageOverrides"
        "llm.provider:syncLLMConfig"
        "llm.ollamaURL:syncLLMConfig"
        "llm.ollamaModel:syncLLMConfig"
        "llm.openaiURL:syncLLMConfig"
        "llm.model:syncLLMConfig"
        "llm.enabled:syncLLMConfig"
        "webhookSlackURL:syncWebhookConfig"
        "webhookTeamsURL:syncWebhookConfig"
        "webhookDiscordURL:syncWebhookConfig"
        "webhookPagerDutyKey:syncWebhookConfig"
        "webhookMinSeverity:syncWebhookConfig"
    )

    # Verify each named sync function exists.
    for binding in "${DAEMON_BINDINGS[@]}"; do
        key="${binding%%:*}"
        sync_fn="${binding##*:}"
        if ! grep -qE "func[[:space:]]+$sync_fn[[:space:]]*\(" "$SETTINGS_FILE"; then
            err "Settings binding \"$key\" references missing sync function $sync_fn()"
        fi
    done

    # Find every @AppStorage in SettingsView and ensure it's in either
    # IGNORE or DAEMON_BINDINGS. New bindings that aren't classified
    # are flagged so we don't accidentally ship another orphan.
    declared_keys=$(grep -oE '@AppStorage\("[^"]+"' "$SETTINGS_FILE" \
        | sed -E 's/@AppStorage\("([^"]+)"/\1/')
    for key in $declared_keys; do
        # Match against IGNORE list
        skip=0
        for ig in "${UI_ONLY_KEYS[@]}"; do
            if [[ "$key" == "$ig" ]]; then skip=1; break; fi
        done
        if [[ $skip -eq 1 ]]; then continue; fi
        # Match against DAEMON_BINDINGS list
        in_daemon=0
        for binding in "${DAEMON_BINDINGS[@]}"; do
            if [[ "$key" == "${binding%%:*}" ]]; then in_daemon=1; break; fi
        done
        if [[ $in_daemon -eq 0 ]]; then
            warn "Unclassified @AppStorage(\"$key\"): add to UI_ONLY_KEYS (UI-only) or DAEMON_BINDINGS (must reach daemon)"
        fi
    done

    if [[ $ERRORS -eq 0 ]]; then
        ok "All daemon-bound Settings keys have a sync function"
    fi
fi

# ---------------------------------------------------------------------
# PASS 2 — direct-insert audit (AlertSink single-sink invariant)
# ---------------------------------------------------------------------

section "PASS 2 — AlertSink single-sink invariant"

# Every alertStore.insert call in production code outside AlertSink
# itself is either a regression of the v1.6.9 NoiseFilter-layering bug
# class, or a documented exception. Two exceptions exist in
# DaemonSetup.swift (lines 229 + 265 as of v1.6.19); they're audited
# because the closures capture alertStore before AlertSink is built.

# Allowed file: AlertSink.swift uses alertStore.insert internally.
# Allowed exception sites: DaemonSetup.swift self-defense + ES-health.
ALLOWED_EXCEPTION_FILE="Sources/MacCrabAgentKit/DaemonSetup.swift"
ALLOWED_EXCEPTION_COUNT_TARGET=2

# Find all production-code direct inserts.
direct_inserts=$(grep -rnE 'alertStore\.insert' Sources \
    --include='*.swift' 2>/dev/null \
    | grep -v 'AlertSink\.swift')

# Lines in DaemonState.swift are docstring references, not real calls.
direct_inserts=$(echo "$direct_inserts" | grep -v 'DaemonState\.swift')

# Strip any inside the AlertSink directory itself if path differs.
direct_inserts=$(echo "$direct_inserts" | grep -v '/AlertSink\.swift')

# Count unique non-exception sites.
exception_count=$(echo "$direct_inserts" | grep -c "$ALLOWED_EXCEPTION_FILE" || true)
total_count=$(echo "$direct_inserts" | grep -cE '\S' || true)
unauthorized_count=$(( total_count - exception_count ))

if [[ "$unauthorized_count" -gt 0 ]]; then
    err "$unauthorized_count direct alertStore.insert call(s) outside AlertSink — route through state.alertSink.submit(...) instead:"
    echo "$direct_inserts" | grep -v "$ALLOWED_EXCEPTION_FILE" | sed 's/^/    /' >&2
elif [[ "$exception_count" -ne "$ALLOWED_EXCEPTION_COUNT_TARGET" ]]; then
    warn "DaemonSetup.swift has $exception_count direct insert(s); expected exactly $ALLOWED_EXCEPTION_COUNT_TARGET (audited self-defense + ES-health). Update the exception count or this audit if the audited list changed."
else
    ok "AlertSink chokepoint intact ($exception_count audited DaemonSetup exception(s), 0 unauthorized)"
fi

# ---------------------------------------------------------------------
# PASS 3 — duplicate-source audit
# ---------------------------------------------------------------------
# Pairs of constants that exist in two files and must agree. New entries
# go here whenever a fact gets duplicated across boundaries the type
# system can't bridge.

section "PASS 3 — duplicate-source audit"

# Each entry: "label|extractor1|extractor2"
# extractors are bash command substitutions that print a single value.

check_pair() {
    local label="$1"
    local val_a="$2"
    local val_b="$3"
    if [[ -z "$val_a" || -z "$val_b" ]]; then
        warn "$label: couldn't extract one or both values (a=$val_a b=$val_b) — audit may need updating"
    elif [[ "$val_a" != "$val_b" ]]; then
        err "$label drift: $val_a vs $val_b"
    else
        ok "$label → $val_a"
    fi
}

# Default support directory: appears in DaemonState (docstring), AlertStore
# (init default), and the Casks zap stanza. The init default is the
# canonical value; verify the cask references it.
SUPPORT_DIR_INIT=$(grep -E 'directory: String = "/Library/Application Support/MacCrab"' \
    Sources/MacCrabCore/Storage/AlertStore.swift 2>/dev/null \
    | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
SUPPORT_DIR_CASK=$(grep -E '/Library/Application Support/MacCrab' Casks/maccrab.rb 2>/dev/null \
    | head -1 | grep -oE '/Library/Application Support/MacCrab[^"'\'']*' | head -1 \
    | sed -E 's|^(/Library/Application Support/MacCrab).*|\1|')
check_pair "Default sysext support directory" "$SUPPORT_DIR_INIT" "$SUPPORT_DIR_CASK"

# Sysext launchd label: appears in cask uninstall stanza and in
# SelfDefense path watch list.
SYSEXT_LABEL_CASK=$(grep -oE 'com\.maccrab\.agent[^"'\'' ]*' Casks/maccrab.rb 2>/dev/null \
    | head -1)
SYSEXT_LABEL_SD=$(grep -oE 'com\.maccrab\.agent[^"'\'' ]*' \
    Sources/MacCrabCore/Detection/SelfDefense.swift 2>/dev/null \
    | head -1)
check_pair "Sysext launchd label" "$SYSEXT_LABEL_CASK" "$SYSEXT_LABEL_SD"

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
