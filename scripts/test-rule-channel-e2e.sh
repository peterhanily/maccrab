#!/usr/bin/env bash
# test-rule-channel-e2e.sh — adversarial end-to-end test of the signed
# rule-update channel (maccrabctl rules …) against a LOCAL mock endpoint with a
# generated test key. It drives the REAL RuleChannelFetcher code through the
# happy path AND every dangerous failure mode, asserting that:
#   - a valid, signed, newer manifest installs atomically, and
#   - EVERY bad manifest is refused FAIL-CLOSED, leaving the prior corpus +
#     anti-rollback serial completely intact (the "no broken update to yank"
#     guarantee).
#
# Isolation: it temporarily makes the USER ~/Library MacCrab data dir the
# "newest" so the CLI installs there (writable, restorable) — it NEVER touches
# the live root /Library detector. Everything is snapshotted and restored on
# exit. Requires: a debug maccrabctl build (DEBUG honours the test key path),
# swiftc, python3.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/.build/debug/maccrabctl"
UD="$HOME/Library/Application Support/MacCrab"
PUSHED="$UD/compiled_rules/pushed"
TRUST="$UD/rave_trust_state.json"
EVENTS="$UD/events.db"
WORK="$(mktemp -d /tmp/maccrab-rulechan.XXXXXX)"
PORT=8791
PASS=0; FAIL=0

red(){ printf "\033[31m%s\033[0m\n" "$*"; }
grn(){ printf "\033[32m%s\033[0m\n" "$*"; }
ok(){ grn "  ✓ $*"; PASS=$((PASS+1)); }
bad(){ red "  ✗ $*"; FAIL=$((FAIL+1)); }

[ -x "$BIN" ] || { red "build first: swift build --product maccrabctl"; exit 2; }

# ---- snapshot for restore ------------------------------------------------
ORIG_EVENTS_MTIME="$(stat -f %Sm -t %Y%m%d%H%M.%S "$EVENTS" 2>/dev/null || echo "")"
TRUST_EXISTED=0; [ -f "$TRUST" ] && { TRUST_EXISTED=1; cp -p "$TRUST" "$WORK/trust.orig"; }
# A1-03: the trust-state is now a host-signed envelope; start each run from a
# clean first-seen state so a stale/old-format file can't fail the CLI closed.
# (Restored from trust.orig on exit; the sibling .signkey is left in place.)
rm -f "$TRUST"
PUSHED_EXISTED=0; [ -d "$PUSHED" ] && { PUSHED_EXISTED=1; mv "$PUSHED" "$WORK/pushed.orig"; }

cleanup() {
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  rm -rf "$PUSHED"
  if [ "$PUSHED_EXISTED" = 1 ]; then mkdir -p "$(dirname "$PUSHED")"; mv "$WORK/pushed.orig" "$PUSHED"; fi
  if [ "$TRUST_EXISTED" = 1 ]; then cp -p "$WORK/trust.orig" "$TRUST"; else rm -f "$TRUST"; fi
  [ -n "$ORIG_EVENTS_MTIME" ] && touch -t "$ORIG_EVENTS_MTIME" "$EVENTS" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- signer (CryptoKit Ed25519, matches the client's verify) -------------
cat > "$WORK/signer.swift" <<'SWIFT'
import Foundation
import CryptoKit
let a = CommandLine.arguments
func die(_ m: String) -> Never { FileHandle.standardError.write(Data((m+"\n").utf8)); exit(2) }
switch a.count >= 2 ? a[1] : "" {
case "keygen":
  guard a.count == 4 else { die("keygen <priv> <pub>") }
  let k = Curve25519.Signing.PrivateKey()
  try! k.rawRepresentation.write(to: URL(fileURLWithPath: a[2]))
  try! k.publicKey.rawRepresentation.write(to: URL(fileURLWithPath: a[3]))
case "sign":
  guard a.count == 5 else { die("sign <priv> <in> <sigOut>") }
  let p = try! Curve25519.Signing.PrivateKey(rawRepresentation: try! Data(contentsOf: URL(fileURLWithPath: a[2])))
  let m = try! Data(contentsOf: URL(fileURLWithPath: a[3]))
  try! p.signature(for: m).write(to: URL(fileURLWithPath: a[4]))
default: die("usage: signer keygen|sign")
}
SWIFT
swiftc -O "$WORK/signer.swift" -o "$WORK/signer" 2>"$WORK/signer.build.log" \
  || { red "signer compile failed:"; cat "$WORK/signer.build.log"; exit 2; }

"$WORK/signer" keygen "$WORK/priv_a" "$WORK/rules.pub"
"$WORK/signer" keygen "$WORK/priv_b" "$WORK/pub_b"     # wrong key
export MACCRAB_RAVE_RULES_PUB_PATH="$WORK/rules.pub"

# ---- mock endpoint -------------------------------------------------------
mkdir -p "$WORK/web"
# Clear any straggler server on the port (e.g. from a previous aborted run),
# then start ours and health-check it before proceeding.
lsof -ti tcp:"$PORT" 2>/dev/null | xargs kill -9 2>/dev/null; sleep 0.5
( cd "$WORK/web" && exec python3 -m http.server "$PORT" >/dev/null 2>&1 ) &
SRV_PID=$!
BASE="http://127.0.0.1:$PORT/"
echo "maccrab-e2e-health" > "$WORK/web/health.txt"
healthy=0
for _ in $(seq 1 20); do
  if curl -fsS "${BASE}health.txt" 2>/dev/null | grep -q maccrab-e2e-health; then healthy=1; break; fi
  sleep 0.25
done
[ "$healthy" = 1 ] || { red "mock server failed to come up on $PORT (serving $WORK/web)"; exit 2; }

# ---- manifest builder (valid CompiledRule shape) -------------------------
# build_manifest <serial> <corpus> <minver|-> <nrules> <unsafe_id|-> <out>
build_manifest() {
python3 - "$@" <<'PY'
import sys, json
serial, corpus, minver, nrules, unsafe, out = sys.argv[1:7]
def rule(rid):
    return {
        "id": rid, "title": "E2E test rule "+rid,
        "description": "rule-channel e2e harness fixture", "level": "low",
        "suppressible": True, "tags": ["attack.discovery"],
        "logsource": {"category": "file_event", "product": "macos"},
        "predicates": [{"field": "file.path", "modifier": "contains",
                        "values": ["/maccrab-e2e-nomatch-zzz/"], "negate": False}],
        "condition": "all_of", "falsepositives": ["n/a"],
        "enabled": True, "status": "experimental",
    }
ids = [f"maccrab.e2e.rule{i}" for i in range(int(nrules))]
if unsafe != "-":
    ids[0] = unsafe
m = {"serial": int(serial), "corpus_version": corpus, "rules": [rule(i) for i in ids]}
if minver != "-":
    m["min_maccrab_version"] = minver
open(out, "w").write(json.dumps(m, indent=2))
PY
}

serve() {  # serve a freshly-built+signed manifest (valid sig with key A)
  build_manifest "$@" "$WORK/web/rules-manifest.json"
  "$WORK/signer" sign "$WORK/priv_a" "$WORK/web/rules-manifest.json" "$WORK/web/rules-manifest.json.sig"
}

# A1-03: rave_trust_state.json is now a host-signed envelope — the marks live
# under "body" (older builds wrote them at the top level). Read either shape.
serial_now() { python3 -c "
import json
try:
    d = json.load(open('$TRUST'))
    b = d['body'] if isinstance(d.get('body'), dict) else d
    print(b.get('rules_manifest_serial', 'none'))
except Exception:
    print('none')
"; }
pushed_count() { ls -1 "$PUSHED"/*.json 2>/dev/null | wc -l | tr -d ' '; }

run_update(){ "$BIN" rules update --rules-base "$BASE" 2>&1; }
run_check(){  "$BIN" rules check-updates --rules-base "$BASE" 2>&1; }

assert_refuse() { # <label>; state must be unchanged
  local label="$1"; local s0 c0 out rc
  s0="$(serial_now)"; c0="$(pushed_count)"
  out="$(run_update)"; rc=$?
  local s1 c1; s1="$(serial_now)"; c1="$(pushed_count)"
  if [ $rc -ne 0 ] && [ "$s0" = "$s1" ] && [ "$c0" = "$c1" ]; then
    ok "$label — refused, prior corpus intact (serial=$s1 rules=$c1)"
  else
    bad "$label — rc=$rc serial $s0->$s1 rules $c0->$c1 :: $(echo "$out" | tail -1)"
  fi
}

assert_install() { # <label> <expect_serial> <expect_count>
  local label="$1" es="$2" ec="$3" out rc
  out="$(run_update)"; rc=$?
  local s1 c1; s1="$(serial_now)"; c1="$(pushed_count)"
  if [ $rc -eq 0 ] && [ "$s1" = "$es" ] && [ "$c1" = "$ec" ]; then
    ok "$label — installed (serial=$s1 rules=$c1)"
  else
    bad "$label — rc=$rc serial=$s1(want $es) rules=$c1(want $ec) :: $(echo "$out" | tail -1)"
  fi
}

# ---- redirect the CLI to the USER data dir (restored on exit) ------------
touch -t 203012312359 "$EVENTS"
INSTALLED_DIR="$("$BIN" rules status 2>&1 | sed -n 's/.*(at \(.*\))/\1/p')"
case "$INSTALLED_DIR" in
  "$HOME"/*) grn "Isolated to user dir: $INSTALLED_DIR";;
  *) red "Could not redirect to user dir (got: $INSTALLED_DIR) — aborting to avoid touching the live detector"; exit 2;;
esac

echo "════════ rule-channel adversarial e2e ════════"

# T1 — missing key fails closed (channel inert without rules.pub)
( unset MACCRAB_RAVE_RULES_PUB_PATH; "$BIN" rules check-updates --rules-base "$BASE" >/dev/null 2>&1 ) \
  && bad "T1 missing-key should refuse" || ok "T1 missing key → channel refuses (fail-closed)"

# T2 — check-updates on a valid signed manifest (read-only, no state change)
serve 100 "e2e-1.0" - 3 -
c0="$(serial_now)"
if run_check | grep -q "serial 100"; then ok "T2 check-updates verifies + reports serial 100"; else bad "T2 check-updates"; fi
[ "$(serial_now)" = "$c0" ] && ok "T2 check-updates wrote no state" || bad "T2 check mutated state"

# T3 — happy install
assert_install "T3 install serial 100 / 3 rules" 100 3
# T4 — idempotent re-install of the same serial (accepted, no rollback)
assert_install "T4 re-install same serial 100" 100 3
# T5 — newer serial installs (more rules)
serve 101 "e2e-1.1" - 5 -
assert_install "T5 upgrade to serial 101 / 5 rules" 101 5

# T6 — ROLLBACK to an older serial is refused; corpus intact
serve 50 "e2e-old" - 9 -
assert_refuse "T6 rollback (serial 50 < 101)"

# T7 — corrupt signature
serve 102 "e2e-badsig" - 4 -
printf 'corrupted' >> "$WORK/web/rules-manifest.json.sig"
assert_refuse "T7 corrupt signature"

# T8 — wrong signing key
build_manifest 102 "e2e-wrongkey" - 4 - "$WORK/web/rules-manifest.json"
"$WORK/signer" sign "$WORK/priv_b" "$WORK/web/rules-manifest.json" "$WORK/web/rules-manifest.json.sig"
assert_refuse "T8 wrong signing key"

# T9 — tampered body (valid sig over the ORIGINAL bytes, body changed after)
serve 102 "e2e-tamper" - 4 -
printf '\n ' >> "$WORK/web/rules-manifest.json"     # mutate after signing
assert_refuse "T9 tampered manifest body"

# T10 — malformed JSON
printf '{ this is not json ' > "$WORK/web/rules-manifest.json"
"$WORK/signer" sign "$WORK/priv_a" "$WORK/web/rules-manifest.json" "$WORK/web/rules-manifest.json.sig"
assert_refuse "T10 malformed JSON"

# T11 — missing serial
python3 -c "import json; json.dump({'corpus_version':'x','rules':[]}, open('$WORK/web/rules-manifest.json','w'))"
"$WORK/signer" sign "$WORK/priv_a" "$WORK/web/rules-manifest.json" "$WORK/web/rules-manifest.json.sig"
assert_refuse "T11 missing serial (anti-rollback needs one)"

# T12 — missing rules array
python3 -c "import json; json.dump({'serial':200,'corpus_version':'x'}, open('$WORK/web/rules-manifest.json','w'))"
"$WORK/signer" sign "$WORK/priv_a" "$WORK/web/rules-manifest.json" "$WORK/web/rules-manifest.json.sig"
assert_refuse "T12 missing rules array"

# T13 — path-traversal rule id rejects the WHOLE manifest (no partial corpus)
serve 103 "e2e-evilid" - 3 "../../../../tmp/evil"
assert_refuse "T13 unsafe rule id (whole manifest refused)"

# T14 — version floor too high
serve 103 "e2e-floor" 999.0.0 3 -
assert_refuse "T14 version floor 999.0.0"

# T15 — channel still installs after the assault (recovery)
serve 110 "e2e-recover" - 2 -
assert_install "T15 recover: serial 110 / 2 rules" 110 2

# T16 — installed files are valid CompiledRule JSON named by id
if python3 -c "import json,glob,sys; sys.exit(0 if all('id' in json.load(open(f)) for f in glob.glob('$PUSHED/*.json')) else 1)"; then
  ok "T16 installed pushed rules are valid CompiledRule JSON"
else bad "T16 installed pushed rules invalid"; fi

echo "════════════════════════════════════════════════"
printf "PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && grn "rule-channel e2e: ALL GREEN" || red "rule-channel e2e: FAILURES"
exit "$FAIL"
