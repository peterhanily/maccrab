#!/bin/bash
# Isolated policy tests. Source definitions only: do not run uninstall, open,
# systemextensionsctl, process stopping, or any cleanup command. No command
# mocks are used; every fixture is ordinary captured-listing text.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/uninstall.sh"

checks=0
assert_state() {
    local expected="$1" command_status="$2" listing="$3" actual
    actual="$(printf '%s\n' "$listing" | maccrab_classify_sysext_listing "$command_status")"
    if [ "$actual" != "$expected" ]; then
        printf 'FAIL: expected %s, got %s\n' "$expected" "$actual" >&2
        exit 1
    fi
    if maccrab_removal_permitted "$actual"; then
        if [ "$expected" != absent ]; then
            printf 'FAIL: cleanup permitted for %s\n' "$expected" >&2
            exit 1
        fi
    elif [ "$expected" = absent ]; then
        printf 'FAIL: verified absence did not permit cleanup\n' >&2
        exit 1
    fi
    checks=$((checks + 1))
}

zero='0 extension(s)'
active='1 extension(s)
--- com.apple.system_extension.endpoint_security
 enabled active teamID bundleID (version) name [state]
* * 79S425CW99 com.maccrab.agent (1.22.0/1119) MacCrab Detection Engine [activated enabled]'
pending_reboot='1 extension(s)
--- com.apple.system_extension.endpoint_security
 enabled active teamID bundleID (version) name [state]
  79S425CW99 com.maccrab.agent (1.22.0/1119) MacCrab Detection Engine [terminated waiting to uninstall on reboot]'
approval='1 extension(s)
--- com.apple.system_extension.endpoint_security
 enabled active teamID bundleID (version) name [state]
  79S425CW99 com.maccrab.agent (1.22.0/1119) MacCrab Detection Engine [activated waiting for user]'
cancelled='1 extension(s)
--- com.apple.system_extension.endpoint_security
 enabled active teamID bundleID (version) name [state]
  79S425CW99 com.maccrab.agent (1.22.0/1119) MacCrab Detection Engine [deactivation cancelled]'
unrelated='1 extension(s)
--- com.apple.system_extension.network_extension
 enabled active teamID bundleID (version) name [state]
* * ABCDE12345 com.example.network (1.0/1) Other Product [activated enabled]'
legacy='1 extension(s)
--- com.apple.system_extension.endpoint_security
 enabled active teamID bundleID (version) name [state]
* * 79S425CW99 com.maccrab.agent.systemextension (1.0/1) MacCrab [activated enabled]'
wrong_team='1 extension(s)
--- com.apple.system_extension.endpoint_security
 enabled active teamID bundleID (version) name [state]
* * ABCDE12345 com.maccrab.agent (1.0/1) MacCrab [activated enabled]'

assert_state absent 0 "$zero"
assert_state absent 0 "$unrelated"
assert_state present 0 "$active"
assert_state pending_reboot 0 "$pending_reboot"
assert_state present 0 "$approval"
assert_state cancelled 0 "$cancelled"
assert_state present 0 "$legacy"
assert_state unknown 0 "$wrong_team"
# Command failure cannot turn even an apparently empty listing into proof.
assert_state unknown 1 "$zero"
assert_state unknown 1 'Operation not permitted'
assert_state unknown 0 ''
assert_state unknown 0 'A future unsupported listing format'
# A successful but truncated or inconsistent listing is still not absence.
assert_state unknown 0 '1 extension(s)'
assert_state unknown 0 "0 extension(s)
* * 79S425CW99 com.maccrab.agent (1.22.0/1119) MacCrab [activated enabled]"
assert_state unknown 0 "1 extension(s)
* * 79S425CW99 com.maccrab.agent (1.22.0/1119) MacCrab [truncated"
# Data-removal consent cannot change the OS-completion predicate.
AUTO_YES=true
assert_state present 0 "$active"
assert_state pending_reboot 0 "$pending_reboot"
assert_state unknown 1 "$zero"

printf 'Uninstall state policy: %s isolated checks passed. No uninstall actions executed.\n' "$checks"
