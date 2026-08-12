#!/bin/bash
# MacCrab Install Script
#
# v1.3.0 onwards: maccrabd is no longer a standalone binary. The ES
# detection engine lives inside MacCrab.app as a system extension that
# gets activated when you first launch the app and approve it in
# System Settings > General > Login Items & Extensions. This script:
#
#   1. Cleans up legacy LaunchDaemons and provisioning profiles left
#      over from 1.2.x installs on the same machine
#   2. Prepares /Library/Application Support/MacCrab without modifying an
#      existing compiled-rule corpus
#   3. Stages, verifies, and publishes MacCrab.app to /Applications
#   4. Installs maccrabctl + maccrab-mcp CLI links
#   5. Reminds the user to launch the app and approve the extension
#
# Must be run with sudo. Homebrew cask users never invoke this directly — the
# cask's postflight block mirrors the same steps.

# Resolve both supported layouts without guessing from a fixed parent depth:
#
#   repository: <root>/scripts/install.sh -> <root>
#   release DMG: <mount>/install.sh       -> <mount>
#
# The pre-fix unconditional dirname(dirname($0)) made the DMG case resolve to
# /Volumes, so it found no MacCrab.app at all.
maccrab_resolve_payload_root() {
    local script_dir="$1"
    local canonical_dir
    canonical_dir="$(cd "$script_dir" 2>/dev/null && /bin/pwd -P)" || return 1

    if [ -d "$canonical_dir/MacCrab.app" ] \
            && [ ! -L "$canonical_dir/MacCrab.app" ] \
            && [ -f "$canonical_dir/MacCrab.app/Contents/Info.plist" ]; then
        printf '%s\n' "$canonical_dir"
        return 0
    fi

    if [ "$(/usr/bin/basename "$canonical_dir")" = "scripts" ] \
            && [ -f "$canonical_dir/../Package.swift" ]; then
        (cd "$canonical_dir/.." && /bin/pwd -P)
        return 0
    fi

    return 1
}

# cp -R preserves the source modes.  Release builds can be assembled under
# umask 077, and changing ownership to root without widening read/traverse bits
# turns a valid app into a root-only bundle.  Preserve the executable set while
# making all bundle content readable/traversable, then explicitly protect the
# known entry points if a transport stripped their execute bit.
maccrab_validate_app_executable_roots() {
    local app="$1"
    [ -d "$app" ] && [ ! -L "$app" ] || return 1
    [ -d "$app/Contents" ] && [ ! -L "$app/Contents" ] || return 1
    [ -d "$app/Contents/MacOS" ] && [ ! -L "$app/Contents/MacOS" ] || return 1
    [ -f "$app/Contents/MacOS/MacCrab" ] \
        && [ ! -L "$app/Contents/MacOS/MacCrab" ] || return 1

    # The app/framework resource tree legitimately contains symlinks, but the
    # executable roots we chmod must not. Reject links (including a linked
    # executable-directory carrier) before any privileged chmod can follow an
    # attacker-selected target in a modified/manual payload.
    if [ -e "$app/Contents/Resources/bin" ] || [ -L "$app/Contents/Resources/bin" ]; then
        [ -d "$app/Contents/Resources" ] && [ ! -L "$app/Contents/Resources" ] \
            || return 1
        [ -d "$app/Contents/Resources/bin" ] \
            && [ ! -L "$app/Contents/Resources/bin" ] || return 1
        if /usr/bin/find "$app/Contents/Resources/bin" -type l -print -quit \
                | /usr/bin/grep -q .; then
            return 1
        fi
    fi
    if [ -e "$app/Contents/Library/SystemExtensions" ] \
            || [ -L "$app/Contents/Library/SystemExtensions" ]; then
        [ -d "$app/Contents/Library" ] && [ ! -L "$app/Contents/Library" ] \
            || return 1
        [ -d "$app/Contents/Library/SystemExtensions" ] \
            && [ ! -L "$app/Contents/Library/SystemExtensions" ] || return 1
        if /usr/bin/find "$app/Contents/Library/SystemExtensions" \
                -type l -print -quit | /usr/bin/grep -q .; then
            return 1
        fi
    fi
}

# Normalize bundle symlink metadata without ever dereferencing a link.  Sparkle
# frameworks legitimately use relative symlinks, but a payload assembled under
# umask 077 can otherwise become root-owned lrwx------ after sudo installation.
# Explicit -P prevents traversal through a directory link and chmod -h applies
# 0755 to the link object rather than to an attacker-selected target.
maccrab_normalize_app_symlink_modes_no_follow() {
    local app="$1"
    [ -d "$app" ] && [ ! -L "$app" ] || return 1
    /usr/bin/find -P "$app" -type l -exec /bin/chmod -h 0755 {} + || return 1
    if /usr/bin/find -P "$app" -type l ! -perm 0755 -print -quit \
            | /usr/bin/grep . >/dev/null; then
        return 1
    fi
}

maccrab_normalize_app_modes() {
    local app="$1"
    maccrab_validate_app_executable_roots "$app" || return 1

    # Metadata is outside the code-signature byte seal. A legitimate signed app
    # can still arrive with an inherited ACL or append/immutable flag that makes
    # its root-owned installation writable by another identity or impossible to
    # replace. Do not follow legitimate bundle symlinks while clearing it.
    /usr/bin/find "$app" \( -type d -o -type f \) \
        -exec /usr/bin/chflags \
            nouchg,nouappnd,nodatavault,noschg,nosappnd,nosunlnk,nodataless {} + \
        || return 1
    /usr/bin/find "$app" \( -type d -o -type f \) \
        -exec /bin/chmod -N {} + || return 1
    /usr/bin/find "$app" -type d -exec /bin/chmod a+rx,go-w {} +
    /usr/bin/find "$app" -type f -exec /bin/chmod a+r,go-w {} +
    /usr/bin/find "$app" -type f -perm -u+x -exec /bin/chmod a+x {} +
    maccrab_normalize_app_symlink_modes_no_follow "$app" || return 1
    /bin/chmod 0755 "$app/Contents/MacOS/MacCrab"
    if [ -d "$app/Contents/Resources/bin" ]; then
        /usr/bin/find "$app/Contents/Resources/bin" -type f \
            -exec /bin/chmod 0755 {} +
    fi
    if [ -d "$app/Contents/Library/SystemExtensions" ]; then
        /usr/bin/find "$app/Contents/Library/SystemExtensions" -type f \
            -path '*/Contents/MacOS/*' -exec /bin/chmod 0755 {} +
    fi
    if /usr/bin/find "$app" \
            \( -flags +uchg -o -flags +uappnd -o -flags +datavault \
               -o -flags +schg -o -flags +sappnd -o -flags +sunlnk \
               -o -flags +dataless \) -print \
            | /usr/bin/grep . >/dev/null; then
        return 1
    fi
    if /usr/bin/find "$app" \( -type d -o -type f \) \
            -exec /bin/ls -lde {} + \
            | /usr/bin/grep -E '^[[:space:]][[:digit:]]+: ' >/dev/null; then
        return 1
    fi
}

# One indirection keeps the rename transaction fault-injectable without putting
# a configurable executable path on the privileged install surface. Tests that
# source this script may replace the function; an executed installer always
# defines this fixed /bin/mv implementation before entering the transaction.
maccrab_move_path() {
    /bin/mv "$1" "$2"
}

# Restore Previous-MacCrab.app without ever passing an existing directory as
# mv's destination. Plain BSD mv nests the source inside an existing directory,
# which is the opposite of rollback. If either rename fails, keep Previous (and
# any displaced target) inside the root-only workspace for the next recovery
# attempt; callers must not delete the workspace on failure.
maccrab_restore_previous_app() {
    local target_app="$1"
    local previous_app="$2"
    local displaced_app="$3"

    [ -d "$previous_app" ] && [ ! -L "$previous_app" ] || return 1
    if [ -e "$target_app" ] || [ -L "$target_app" ]; then
        [ -d "$target_app" ] && [ ! -L "$target_app" ] || return 1
        [ ! -e "$displaced_app" ] && [ ! -L "$displaced_app" ] || return 1
        maccrab_move_path "$target_app" "$displaced_app" || return 1
    fi

    # Re-check immediately before the restore. This prevents ordinary failure
    # paths from nesting Previous inside a surviving target directory.
    if [ -e "$target_app" ] || [ -L "$target_app" ]; then
        return 1
    fi
    if maccrab_move_path "$previous_app" "$target_app"; then
        return 0
    fi

    # Best effort: put the displaced app back at the canonical path. Whether
    # this succeeds or not, Previous remains recoverable in the workspace.
    if [ -d "$displaced_app" ] && [ ! -L "$displaced_app" ] \
            && [ ! -e "$target_app" ] && [ ! -L "$target_app" ]; then
        maccrab_move_path "$displaced_app" "$target_app" || true
    fi
    return 1
}

# Complete rollback and discard transaction-only copies only after Previous has
# reached the canonical target. On any failed rename this function returns with
# the locked workspace intact, making the next installer invocation—not rm—the
# owner of recovery.
maccrab_rollback_app_install() {
    local target_app="$1"
    local work_root="$2"
    local staged_app="$work_root/New-MacCrab.app"
    local previous_app="$work_root/Previous-MacCrab.app"
    local interrupted_app="$work_root/Interrupted-MacCrab.app"

    if [ -d "$previous_app" ] && [ ! -L "$previous_app" ]; then
        maccrab_restore_previous_app \
            "$target_app" "$previous_app" "$interrupted_app" || return 1
    elif [ -e "$target_app" ] || [ -L "$target_app" ]; then
        [ -d "$target_app" ] && [ ! -L "$target_app" ] \
            && [ ! -e "$interrupted_app" ] && [ ! -L "$interrupted_app" ] \
            && maccrab_move_path "$target_app" "$interrupted_app" \
            || return 1
    fi

    [ ! -d "$staged_app" ] || /bin/rm -rf "$staged_app"
    [ ! -d "$interrupted_app" ] || /bin/rm -rf "$interrupted_app"
    /bin/rmdir "$work_root"
}

# Recover the only three names an interrupted publication can leave behind.
# Recovery always favors the predecessor: if both the target and Previous exist,
# the prior transaction reached its second rename but not its cleanup, so put
# Previous back and discard the uncommitted target.  The fixed root also acts as
# an atomic mkdir lock; concurrent installers cannot create a second workspace.
maccrab_recover_interrupted_app_install() {
    local target_app="$1"
    local required_uid="${2:-0}"
    local target_parent work_root staged_app previous_app interrupted_app unknown

    target_parent="$(/usr/bin/dirname "$target_app")"
    work_root="$target_parent/.MacCrab-install"
    staged_app="$work_root/New-MacCrab.app"
    previous_app="$work_root/Previous-MacCrab.app"
    interrupted_app="$work_root/Interrupted-MacCrab.app"
    if [ ! -e "$work_root" ] && [ ! -L "$work_root" ]; then
        return 0
    fi
    [ -d "$work_root" ] && [ ! -L "$work_root" ] || return 1
    [ "$(/usr/bin/stat -f '%u:%Lp' "$work_root")" = "$required_uid:700" ] || return 1
    unknown=$(/usr/bin/find "$work_root" -mindepth 1 -maxdepth 1 \
        ! -name New-MacCrab.app \
        ! -name Previous-MacCrab.app \
        ! -name Interrupted-MacCrab.app -print -quit)
    [ -z "$unknown" ] || return 1
    for candidate in "$staged_app" "$previous_app" "$interrupted_app"; do
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            [ -d "$candidate" ] && [ ! -L "$candidate" ] || return 1
        fi
    done

    if [ -d "$previous_app" ]; then
        maccrab_restore_previous_app \
            "$target_app" "$previous_app" "$interrupted_app" || return 1
    elif [ ! -d "$target_app" ] && [ -d "$interrupted_app" ]; then
        # No predecessor remains to authenticate this ambiguous state. Preserve
        # it for manual inspection rather than deleting or publishing it.
        return 1
    fi

    [ ! -d "$staged_app" ] || /bin/rm -rf "$staged_app"
    [ ! -d "$interrupted_app" ] || /bin/rm -rf "$interrupted_app"
    /bin/rmdir "$work_root"
}

# Publish a fully copied and designated-signature-verified app with same-volume
# renames. The existing app is untouched until the staged copy passes every
# gate. The deterministic recovery above closes the two-rename crash gap on the
# next invocation and always rolls an incomplete transaction back to the old
# app rather than guessing that the new one committed.
maccrab_install_app_atomically() {
    local source_app="$1"
    local target_app="$2"
    local target_parent work_root staged_app previous_app
    local app_requirement saved_umask

    maccrab_validate_app_executable_roots "$source_app" || return 1
    target_parent="$(/usr/bin/dirname "$target_app")"
    [ -d "$target_parent" ] && [ ! -L "$target_parent" ] || return 1
    target_parent="$(cd "$target_parent" && /bin/pwd -P)" || return 1
    target_app="$target_parent/$(/usr/bin/basename "$target_app")"
    [ "$(/usr/bin/basename "$target_app")" = "MacCrab.app" ] || return 1
    if [ -e "$target_app" ] || [ -L "$target_app" ]; then
        [ -d "$target_app" ] && [ ! -L "$target_app" ] || return 1
    fi

    maccrab_recover_interrupted_app_install "$target_app" || return 1
    work_root="$target_parent/.MacCrab-install"
    saved_umask=$(umask)
    umask 077
    if ! /bin/mkdir "$work_root"; then
        umask "$saved_umask"
        return 1
    fi
    umask "$saved_umask"
    /bin/chmod 0700 "$work_root" || return 1
    staged_app="$work_root/New-MacCrab.app"
    previous_app="$work_root/Previous-MacCrab.app"
    app_requirement='identifier "com.maccrab.app" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "79S425CW99"'

    if ! /usr/bin/ditto "$source_app" "$staged_app"; then
        /bin/rm -rf "$work_root"
        return 1
    fi
    if ! /usr/sbin/chown -R root:admin "$staged_app" \
            || ! maccrab_normalize_app_modes "$staged_app" \
            || ! /usr/bin/codesign --verify --deep --strict "$staged_app" \
            || ! /usr/bin/codesign --verify --strict \
                -R="$app_requirement" "$staged_app"; then
        /bin/rm -rf "$work_root"
        return 1
    fi

    if [ -d "$target_app" ]; then
        if ! maccrab_move_path "$target_app" "$previous_app"; then
            /bin/rm -rf "$work_root"
            return 1
        fi
    fi
    if ! maccrab_move_path "$staged_app" "$target_app"; then
        if ! maccrab_rollback_app_install "$target_app" "$work_root"; then
            echo "ERROR: failed to restore $target_app from $previous_app; recovery copies retained in $work_root" >&2
        fi
        return 1
    fi

    # Verify the published pathname too.  A same-volume rename should not alter
    # bytes, but this turns a surprising filesystem/policy failure into a
    # rollback instead of discarding the known-good predecessor.
    if ! /usr/bin/codesign --verify --deep --strict "$target_app" \
            || ! /usr/bin/codesign --verify --strict \
                -R="$app_requirement" "$target_app"; then
        if ! maccrab_rollback_app_install "$target_app" "$work_root"; then
            echo "ERROR: failed to restore $target_app from $previous_app; recovery copies retained in $work_root" >&2
        fi
        return 1
    fi

    if [ -d "$previous_app" ]; then
        /bin/rm -rf "$previous_app"
    fi
    /bin/rmdir "$work_root"
}

# Tests source this file for the pure helpers above.  Never run the privileged
# installer body merely because another script imported those functions.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ! PROJECT_DIR="$(maccrab_resolve_payload_root "$SCRIPT_DIR")"; then
    echo "ERROR: install.sh must be run from a MacCrab source tree or release DMG containing MacCrab.app." >&2
    exit 1
fi

PREFIX="${PREFIX:-/usr/local}"
SUPPORT_DIR="/Library/Application Support/MacCrab"
PLIST_DIR="/Library/LaunchDaemons"
PROFILE_DIR="/Library/MobileDevice/Provisioning Profiles"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

# Check root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo."
fi

cd "$PROJECT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         🦀 MacCrab Installation (v1.3.0+)        ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ─── Step 1: Clean up legacy 1.2.x artefacts ─────────────────────────
# 1.2.x shipped maccrabd as a LaunchDaemon with a stapled provisioning
# profile installed system-wide. 1.3.0 moved to a proper SystemExtension
# activated on first launch of MacCrab.app. Strip the old plumbing so
# the two models don't fight.

info "Cleaning up pre-1.3.0 LaunchDaemons and symlinks..."
for label in com.maccrab.daemon com.maccrab.agent; do
    if launchctl list "$label" &>/dev/null; then
        launchctl unload "$PLIST_DIR/$label.plist" 2>/dev/null || true
    fi
    rm -f "$PLIST_DIR/$label.plist"
done

for stale in "$PREFIX/bin/maccrabd" "/usr/local/bin/maccrabd" "/opt/homebrew/bin/maccrabd"; do
    if [ -L "$stale" ] || [ -f "$stale" ]; then
        rm -f "$stale"
    fi
done

# Legacy system-wide provisioning profile from 1.2.4/1.2.5. Not needed
# once the app's embedded profile takes over.
if [ -d "$PROFILE_DIR" ]; then
    for profile in "$PROFILE_DIR"/*.provisionprofile; do
        [ -f "$profile" ] || continue
        app_id=$(security cms -D -i "$profile" 2>/dev/null \
            | /usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" /dev/stdin 2>/dev/null \
            || echo "")
        if [[ "$app_id" == *"com.maccrab."* ]]; then
            rm -f "$profile"
            info "Removed legacy profile: $(basename "$profile")"
        fi
    done
fi

# ─── Step 2: Support directory ───────────────────────────────────────
info "Creating $SUPPORT_DIR..."
mkdir -p "$SUPPORT_DIR"/{compiled_rules/sequences,compiled_rules/graph,logs,inbox}
chmod 755 "$SUPPORT_DIR"
# v1.10.0 audit fix: inbox/ is the cross-UID IPC drop point for the
# dashboard's "Reduce events.db now" button. Sticky bit (1777) lets
# the user-context dashboard write a marker file the root-context
# sysext picks up + processes, without granting blanket write access
# to the rest of the support dir.
chmod 1777 "$SUPPORT_DIR/inbox"

# Do not pre-seed or update compiled_rules here.  A file-by-file privileged copy
# can corrupt the last-known-good corpus if installation is interrupted or the
# disk fills, and doubles peak rule-storage use.  The root System Extension
# verifies its code-sealed corpus and atomically synchronizes the complete tree
# before it starts any rule reader.  Existing installations remain untouched;
# a first install begins with empty directories that the sysext replaces.
info "Detection rules will be verified and atomically synchronized by the System Extension."

# ─── Step 3: Install MacCrab.app (moved before CLI step) ─────────────
# Order matters: we want to symlink CLIs into the .app's bundled
# Resources/bin so Sparkle in-place updates keep the terminal CLI
# current. Pre-fix the script copied loose CLIs to $PREFIX/bin —
# those copies stayed frozen at install time and went stale after
# every Sparkle update.
if [ -d "$PROJECT_DIR/MacCrab.app" ]; then
    info "Installing MacCrab.app to /Applications..."
    maccrab_install_app_atomically \
        "$PROJECT_DIR/MacCrab.app" "/Applications/MacCrab.app" \
        || error "Staged app copy/signature verification failed; the previous app was retained."
fi

# ─── Step 4: CLI symlinks ────────────────────────────────────────────
# Prefer symlinks pointing at the in-app CLIs over loose copies,
# so the user's terminal `maccrabctl` always tracks the running
# MacCrab.app version (including Sparkle in-place upgrades).
APP_BIN="/Applications/MacCrab.app/Contents/Resources/bin"
mkdir -p "$PREFIX/bin"

if [ -x "$APP_BIN/maccrabctl" ]; then
    info "Linking CLI binaries from $APP_BIN to $PREFIX/bin..."
    for cli in maccrabctl maccrab-mcp; do
        if [ -x "$APP_BIN/$cli" ]; then
            rm -f "$PREFIX/bin/$cli"
            ln -s "$APP_BIN/$cli" "$PREFIX/bin/$cli"
        fi
    done
else
    # Fallback: bundled .app didn't include the CLIs (older build,
    # or the .app wasn't installed). Copy from PROJECT_DIR/bin or
    # .build/release. These are static copies and won't auto-update.
    BIN_SOURCE=""
    if [ -x "$PROJECT_DIR/bin/maccrabctl" ]; then
        BIN_SOURCE="$PROJECT_DIR/bin"
    elif [ -x "$PROJECT_DIR/.build/release/maccrabctl" ]; then
        BIN_SOURCE="$PROJECT_DIR/.build/release"
    fi
    if [ -n "$BIN_SOURCE" ]; then
        warn "MacCrab.app does not contain bundled CLIs — falling back to static copies. These won't auto-update with Sparkle; reinstall after upgrade."
        cp -f "$BIN_SOURCE/maccrabctl" "$PREFIX/bin/maccrabctl"
        chmod 755 "$PREFIX/bin/maccrabctl"
        if [ -f "$BIN_SOURCE/maccrab-mcp" ]; then
            cp -f "$BIN_SOURCE/maccrab-mcp" "$PREFIX/bin/maccrab-mcp"
            chmod 755 "$PREFIX/bin/maccrab-mcp"
        fi
    else
        warn "CLI binaries not found (checked $APP_BIN, bin/, and .build/release/)."
    fi
fi

# Detect Apple Silicon: $PREFIX defaults to /usr/local but Apple
# Silicon's $PATH usually has /opt/homebrew/bin first. If a stale
# brew-cask CLI lives there from an older install, replace it with
# a symlink to the current in-app CLI so `which maccrabctl` returns
# a current binary regardless of which $PREFIX we wrote to.
if [ "$(uname -m)" = "arm64" ] && [ -d "/opt/homebrew/bin" ] && [ -x "$APP_BIN/maccrabctl" ]; then
    for cli in maccrabctl maccrab-mcp; do
        if [ -x "$APP_BIN/$cli" ] && [ "/opt/homebrew/bin" != "$PREFIX/bin" ]; then
            link="/opt/homebrew/bin/$cli"
            target=$(readlink "$link" 2>/dev/null || echo "")
            # Replace if missing OR if it's a stale brew-cask path
            if [ ! -e "$link" ] || [[ "$target" == *"/Caskroom/maccrab/"* ]] || \
               { [ -f "$link" ] && ! [ -L "$link" ]; }; then
                rm -f "$link"
                ln -s "$APP_BIN/$cli" "$link"
                info "Refreshed stale /opt/homebrew/bin/$cli → in-app CLI"
            fi
        fi
    done
fi

echo ""
info "Installation complete."
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  NEXT STEPS                                      ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║                                                  ║"
echo "║  1. Launch /Applications/MacCrab.app             ║"
echo "║  2. Click \"Enable Protection\" on the Overview tab║"
echo "║  3. macOS will prompt you to approve the         ║"
echo "║     Endpoint Security extension in System        ║"
echo "║     Settings > General > Login Items &           ║"
echo "║     Extensions > Endpoint Security Extensions.   ║"
echo "║  4. (Optional) Grant Full Disk Access to         ║"
echo "║     MacCrab.app for full coverage.               ║"
echo "║                                                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Optionally open System Settings to the right pane
read -p "Open MacCrab.app now? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    open "/Applications/MacCrab.app" 2>/dev/null || \
        warn "Could not launch MacCrab.app automatically. Open it from /Applications."
fi
