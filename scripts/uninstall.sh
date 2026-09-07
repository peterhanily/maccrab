#!/bin/bash
# MacCrab Uninstall Script
#
# Removes MacCrab from a v1.3+ install: deactivates the System Extension,
# kills any running processes, removes the .app, removes CLI binaries,
# clears legacy LaunchDaemon plists from pre-1.3 installs, and (with
# confirmation) drops the data directory and Keychain-stored API keys.
#
# Must be run with sudo. The Homebrew Cask uses its own uninstall
# stanza — this script is for users who installed manually from the DMG.
set -euo pipefail

SUPPORT_DIR="/Library/Application Support/MacCrab"
# USER_SUPPORT_DIR is resolved AFTER SUDO_HOME below — under sudo, $HOME is
# /var/root, so a $HOME-based path here would silently skip the real user's data.
PREFIX="${PREFIX:-/usr/local}"
APP_PATH="/Applications/MacCrab.app"
TEAM_ID="79S425CW99"
SYSEXT_ID="com.maccrab.agent"
LEGACY_PLIST_DIR="/Library/LaunchDaemons"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

# Pure classifier: stdin is a captured systemextensionsctl listing; $1 is the
# command's exit status. Only a successful, structurally complete listing can
# prove absence. Sourcing this file defines helpers without running uninstall.
maccrab_classify_sysext_listing() {
    awk -v command_status="${1:-1}" -v target="$SYSEXT_ID" -v team="$TEAM_ID" '
        BEGIN { expected = -1; rows = 0; invalid = 0; present = 0; reboot = 0; cancelled = 0 }
        {
            line = $0
            sub(/\r$/, "", line)
            if (line ~ /^[[:space:]]*$/) next
            if (expected < 0) {
                if (line !~ /^[0-9]+ extension\(s\)$/) { invalid = 1; next }
                split(line, header, " ")
                expected = header[1] + 0
                next
            }
            if (line ~ /^--- / || line ~ /^[[:space:]]*enabled[[:space:]]+active[[:space:]]+teamID[[:space:]]+bundleID/) next
            count = split(line, fields, /[[:space:]]+/)
            row = 0
            for (i = 1; i < count; i++) {
                if (length(fields[i]) == 10 && fields[i] ~ /^[A-Z0-9]+$/ &&
                    fields[i+1] ~ /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$/ &&
                    fields[i+2] ~ /^\(/ && line ~ /\[[^][]+\][[:space:]]*$/) {
                    row = 1
                    rows++
                    if (fields[i+1] == target || fields[i+1] == target ".systemextension") {
                        if (fields[i] != team) invalid = 1
                        present = 1
                        lower = tolower(line)
                        if (lower ~ /uninstall.*(reboot|restart)/) reboot = 1
                        if (lower ~ /cancelled|canceled/) cancelled = 1
                    }
                    break
                }
            }
            if (!row) invalid = 1
        }
        END {
            if (command_status != "0" || invalid || expected < 0 || rows != expected) print "unknown"
            else if (reboot) print "pending_reboot"
            else if (cancelled) print "cancelled"
            else if (present) print "present"
            else print "absent"
        }
    '
}

maccrab_removal_permitted() {
    [ "${1:-unknown}" = "absent" ]
}

maccrab_read_sysext_state() {
    local listing list_status
    if [ ! -x /usr/bin/systemextensionsctl ]; then
        printf '%s\n' unknown
        return
    fi
    if listing="$(LC_ALL=C /usr/bin/systemextensionsctl list 2>/dev/null)"; then
        list_status=0
    else
        list_status=$?
    fi
    printf '%s\n' "$listing" | maccrab_classify_sysext_listing "$list_status"
}

maccrab_require_sysext_absence() {
    local state attempt
    state="$(maccrab_read_sysext_state)"
    if maccrab_removal_permitted "$state"; then
        info "System Extension absence verified."
        return 0
    fi
    case "$state" in
        pending_reboot)
            error "System Extension removal is pending a reboot. MacCrab and its data are preserved. Reboot, then run this script again." ;;
        unknown)
            error "Could not verify System Extension state. MacCrab and its data are preserved. Check systemextensionsctl list, then retry." ;;
        cancelled)
            error "System Extension deactivation was cancelled. MacCrab and its data are preserved. Approve deactivation before retrying." ;;
    esac

    if [ ! -d "$APP_PATH" ]; then
        error "The System Extension is still registered, but $APP_PATH is missing. Data is preserved. Restore the signed app, deactivate its System Extension, then retry."
    fi
    if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = root ]; then
        error "The System Extension is still registered. Run this script with sudo from your signed-in user account so MacCrab can request deactivation. App and data are preserved."
    fi
    info "Asking the installed MacCrab app to deactivate its System Extension..."
    info "Approve the macOS deactivation prompt. Cleanup waits for verified removal."
    if ! sudo -u "$SUDO_USER" /usr/bin/open -a "$APP_PATH" "maccrab://deactivate"; then
        error "Could not request deactivation from $APP_PATH. App and data are preserved. Open MacCrab and deactivate its System Extension, then retry."
    fi

    # Bound observation time, but never use elapsed time as proof of removal.
    # Cancellation/approval delays leave the row present and must block cleanup.
    for ((attempt = 0; attempt < 60; attempt++)); do
        state="$(maccrab_read_sysext_state)"
        if maccrab_removal_permitted "$state"; then
            info "System Extension absence verified."
            return 0
        fi
        case "$state" in
            pending_reboot)
                error "macOS will finish System Extension removal after a reboot. App and data are preserved. Reboot, then run this script again." ;;
            unknown)
                error "System Extension status became unavailable. App and data are preserved. Check systemextensionsctl list before retrying." ;;
            cancelled)
                error "System Extension deactivation was cancelled. App and data are preserved. Approve deactivation before retrying." ;;
        esac
        if [ "$attempt" -lt 59 ]; then sleep 2; fi
    done
    error "System Extension removal is not confirmed. Approval may be pending or cancelled. App and data are preserved. Complete deactivation (and reboot if macOS requests it), then retry."
}

maccrab_uninstall_main() {
AUTO_YES=false
for arg in "$@"; do
    case "$arg" in
        -y|--yes) AUTO_YES=true ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo."
fi

# Step 1 is a mandatory OS-completion gate, including for --yes. No process
# stop, app/CLI removal, data deletion, or credential cleanup precedes it.
maccrab_require_sysext_absence

# ─── Step 2: Stop running processes ──────────────────────────────────
info "Stopping any running MacCrab processes..."
# v1.3+ system extension binary
pkill -x "$SYSEXT_ID" 2>/dev/null || true
# v1.3+ menubar app
pkill -x MacCrab 2>/dev/null || true
# v1.2 legacy daemon (if anyone still has it installed)
pkill -x maccrabd 2>/dev/null || true

# ─── Step 3: Drop legacy v1.2 LaunchDaemon plists ────────────────────
# These are no-ops for v1.3+ installs (the plists won't exist) but
# clean up after users who upgraded across the v1.2 → v1.3 boundary.
for plist in "$LEGACY_PLIST_DIR/com.maccrab.agent.plist" \
             "$LEGACY_PLIST_DIR/com.maccrab.daemon.plist"; do
    if [ -f "$plist" ]; then
        info "Removing legacy LaunchDaemon plist: $plist"
        launchctl unload "$plist" 2>/dev/null || true
        rm -f "$plist"
    fi
done

# ─── Step 4: SMAppService user-side LaunchAgent ─────────────────────
# v1.3+ menubar app registers itself for launch-at-login via
# SMAppService; the registration plist lives in the user's home dir.
# Resolve the invoking user's home dir via DirectoryServices rather
# than eval-based tilde expansion. `dscl . -read` is the canonical
# macOS lookup; the previous eval form worked in practice (SUDO_USER
# is set by sudo(8) from getpwuid()) but the explicit argv path is
# cleaner and easier to audit.
SUDO_HOME="${SUDO_USER:+$(dscl . -read /Users/"$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')}"
USER_LAUNCH_AGENT_DIR="${SUDO_HOME:-$HOME}/Library/LaunchAgents"
# Now that SUDO_HOME is known, resolve the invoking user's data dir from
# SUDO_HOME (NOT $HOME, which is /var/root under sudo). Holds forensic Cases/,
# llm_config.json, user_overrides, and the non-root dev daemon's events.db.
USER_SUPPORT_DIR="${SUDO_HOME:-$HOME}/Library/Application Support/MacCrab"
for variant in "com.maccrab.app.plist" "${TEAM_ID}.com.maccrab.app.plist"; do
    plist="$USER_LAUNCH_AGENT_DIR/$variant"
    if [ -f "$plist" ]; then
        info "Removing launch-at-login: $variant"
        rm -f "$plist"
    fi
done

# ─── Step 5: CLI binaries ────────────────────────────────────────────
info "Removing CLI binaries..."
rm -f "$PREFIX/bin/maccrabctl" "$PREFIX/bin/maccrab-mcp" "$PREFIX/bin/maccrabd"
rm -f "/opt/homebrew/bin/maccrabctl" "/opt/homebrew/bin/maccrab-mcp" "/opt/homebrew/bin/maccrabd"

# ─── Step 6: MacCrab.app ─────────────────────────────────────────────
# Note: with the v1.17 notification rearchitecture, removing the app
# alone stops ALL notification banners regardless of sysext state — the
# app (not the daemon) is the only notification poster now. The sysext
# teardown has already been verified before any cleanup begins.
if [ -d "$APP_PATH" ]; then
    info "Removing $APP_PATH..."
    rm -rf "$APP_PATH"
fi

# ─── Step 7: Optional — data directory + keychain ────────────────────
# Default-no for the data dir: alerts.db, events.db, rule baselines,
# and behavioral baseline state are valuable for forensics. Users who
# want a clean wipe should pass --yes.
if [ "$AUTO_YES" = true ]; then
    REMOVE_DATA=true
else
    echo ""
    read -p "Remove MacCrab data directory (alerts.db, events.db, rules, logs)? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        REMOVE_DATA=true
    else
        REMOVE_DATA=false
    fi
fi

if [ "$REMOVE_DATA" = true ]; then
    info "Removing $SUPPORT_DIR..."
    rm -rf "$SUPPORT_DIR"
    if [ -d "$USER_SUPPORT_DIR" ]; then
        info "Removing $USER_SUPPORT_DIR..."
        rm -rf "$USER_SUPPORT_DIR"
    fi
    # SelfDefense writes tamper forensic logs OUTSIDE the data dirs.
    info "Removing tamper forensic logs..."
    rm -f "/var/log/maccrab_tamper.log" 2>/dev/null || true
    rm -f "${SUDO_HOME:-$HOME}/.maccrab_tamper.log" 2>/dev/null || true
    # Revoke MacCrab's TCC privacy grants (Accessibility, Full Disk Access,
    # Screen Recording, etc.). Gated to the --yes / clean-slate path, mirroring
    # the keychain wipe. The app's grants are keyed to com.maccrab.app and live
    # in the CONSOLE USER's TCC store, so reset them as SUDO_USER; the sysext's
    # grants are system-scoped, so reset com.maccrab.agent* as root. `reset All`
    # clears every service for the bundle in one call. Best-effort.
    if command -v tccutil >/dev/null 2>&1; then
        info "Revoking MacCrab TCC privacy grants..."
        if [ -n "${SUDO_USER:-}" ]; then
            sudo -u "$SUDO_USER" tccutil reset All com.maccrab.app 2>/dev/null || true
        else
            tccutil reset All com.maccrab.app 2>/dev/null || true
        fi
        tccutil reset All com.maccrab.agent 2>/dev/null || true
        tccutil reset All com.maccrab.agent.systemextension 2>/dev/null || true
    fi
    # Keychain-stored API keys live in the user's keychain under
    # service "com.maccrab.secrets". Account names are the rawValues
    # of `SecretsStore.SecretKey` enum (`Sources/MacCrabCore/Storage/
    # SecretsStore.swift`). Pre-fix this list used legacy
    # `maccrab-llm-*` names that have never been the actual account
    # names — every `--yes` uninstall left every API key behind.
    if command -v security >/dev/null 2>&1; then
        info "Removing Keychain-stored API keys + threat-intel + output tokens..."
        for key in \
            llm.claude llm.openai llm.gemini llm.mistral llm.ollama \
            threatintel.virustotal threatintel.abuseipdb threatintel.alienvault \
            threatintel.shodan threatintel.urlscan threatintel.greynoise \
            threatintel.hibp \
            output.splunk_hec output.datadog output.elasticsearch
        do
            if [ -n "${SUDO_USER:-}" ]; then
                sudo -u "$SUDO_USER" security delete-generic-password \
                    -s "com.maccrab.secrets" -a "$key" 2>/dev/null || true
            else
                security delete-generic-password \
                    -s "com.maccrab.secrets" -a "$key" 2>/dev/null || true
            fi
        done
        # Also wipe the database-encryption AES key (separate service).
        if [ -n "${SUDO_USER:-}" ]; then
            sudo -u "$SUDO_USER" security delete-generic-password \
                -s "com.maccrab.db-encryption" 2>/dev/null || true
        else
            security delete-generic-password \
                -s "com.maccrab.db-encryption" 2>/dev/null || true
        fi
    fi
else
    warn "Data preserved at: $SUPPORT_DIR"
    warn "(Keychain-stored API keys also preserved — re-run with --yes to clear.)"
fi

echo ""
info "MacCrab uninstalled."

}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    maccrab_uninstall_main "$@"
fi
