#!/bin/bash
# smoke-install-live-rave.sh — end-to-end install smoke test against the LIVE
# rave.maccrab.com catalog. Asserts the published first-party plugin installs
# through the REAL client path:
#   catalog.json(+.sig) → Ed25519 verify → catalog_serial anti-rollback →
#   per-entry(+.sig) → verify → reserved-namespace gate (honors trust_tier) →
#   version floor → artifact URL ({file} = <id>.maccrabplugin.zip) → download →
#   sha256 == pinned artifact_sha256 → tierB Ed25519 signature → auto-trust
#   (catalog-endorsed signer) → install.
#
# This single test would have caught all three v1.19.1 install blockers
# (namespace-vs-trust_tier, hardcoded {id}.zip filename, missing auto-trust).
#
# Needs: network + a built maccrabctl (swift build --product maccrabctl).
# Run from the repo root:  scripts/smoke-install-live-rave.sh
set -euo pipefail

ID="com.maccrab.forensics.posture-pro"
BIN="${MACCRABCTL:-.build/debug/maccrabctl}"

[ -x "$BIN" ] || { echo "✗ build maccrabctl first: swift build --product maccrabctl" >&2; exit 2; }

echo "→ cleaning any prior install of $ID"
"$BIN" plugin uninstall "$ID" --yes >/dev/null 2>&1 || true

echo "→ search (catalog fetch + Ed25519 verify + list)"
"$BIN" plugin search posture 2>&1 | grep -q "$ID" \
  || { echo "✗ FAIL: 'plugin search' did not list $ID against the live catalog" >&2; exit 1; }

echo "→ install (full verified chain)"
OUT="$("$BIN" plugin install "$ID" --yes 2>&1)" || { echo "✗ FAIL: install errored:" >&2; echo "$OUT" >&2; exit 1; }
echo "$OUT" | sed 's/^/    /'

echo "$OUT" | grep -q "Installed plugin '$ID'" \
  || { echo "✗ FAIL: no install confirmation" >&2; exit 1; }
echo "$OUT" | grep -qE "Trusted:[[:space:]]+yes" \
  || { echo "✗ FAIL: plugin was not auto-trusted (catalog-endorsed signer pin should auto-trust)" >&2; exit 1; }

echo "→ verify (installed plugin verifies against the trust store)"
"$BIN" plugin verify "$ID" 2>&1 | grep -q "$ID" \
  || { echo "✗ FAIL: 'plugin verify' did not confirm $ID" >&2; exit 1; }

echo "✓ live rave install smoke PASSED — $ID installs end-to-end"
