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

AUTO_YES=false
for arg in "$@"; do
    case "$arg" in
        -y|--yes) AUTO_YES=true ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo."
fi

# ─── Step 1: Deactivate the system extension ─────────────────────────
# Must run BEFORE the .app is removed, otherwise sysextd's ledger keeps
# a "pending" entry forever (visible via `systemextensionsctl list`)
# since the bundle it references gets deleted out from under it.
# An ACTIVE Endpoint Security sysext can't be reliably torn down by
# `systemextensionsctl uninstall` from a shell — OSSystemExtensionRequest
# deactivation must be submitted by the SIGNED APP running as the console
# user (and it shows a system approval modal, often completing only after
# a reboot). So when the bundle is still present, ask the app to do it via
# the maccrab://deactivate deep link; keep systemextensionsctl as fallback.
if [ -d "$APP_PATH" ] && [ -n "${SUDO_USER:-}" ]; then
    info "Asking MacCrab to deactivate its system extension (the reliable path)..."
    info "  → Approve the macOS prompt in System Settings > General > Login Items & Extensions."
    sudo -u "$SUDO_USER" open "maccrab://deactivate" 2>/dev/null \
        || warn "Couldn't open the app — falling back to systemextensionsctl."
    # Brief pause so the request reaches sysextd before we kill the app.
    sleep 3
fi
if command -v systemextensionsctl >/dev/null 2>&1; then
    info "Deactivating system extension (fallback)..."
    # Best-effort: this can fail if the extension was never activated
    # (manual maccrabd-only install, or sysextd already cleaned it up).
    systemextensionsctl uninstall "$TEAM_ID" "$SYSEXT_ID" 2>/dev/null \
        || warn "systemextensionsctl uninstall returned non-zero — extension may already be gone."
else
    warn "systemextensionsctl not found — skipping system extension deactivation."
fi

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
# teardown below is for ledger hygiene + stopping detection.
if [ -d "$APP_PATH" ]; then
    info "Removing $APP_PATH..."
    rm -rf "$APP_PATH"
fi

# ─── Step 7: Verify system-extension teardown ────────────────────────
# sysext removal is async and frequently completes only after a reboot
# ("terminated waiting to uninstall on reboot"). Give the operator
# ground truth instead of best-effort silence.
if command -v systemextensionsctl >/dev/null 2>&1; then
    if systemextensionsctl list 2>/dev/null | grep -q "$SYSEXT_ID"; then
        warn "System extension still present — likely pending removal on reboot."
        warn "  → Reboot to finish, then confirm with: systemextensionsctl list"
    else
        info "System extension fully removed."
    fi
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
