#!/usr/bin/env bash
# build-rules-manifest.sh — author + sign a manifest for the v1.20 signed
# out-of-band RULE-UPDATE CHANNEL (consumed by `maccrabctl rules update`).
#
# This is the SENDER side of the channel. (The old scripts/publish-rules.sh
# builds a cosign TARBALL for a different, legacy distribution path; the v1.20
# channel consumes an INLINE Ed25519-signed `rules-manifest.json` instead.)
#
# What it produces (serve both at the channel base URL, e.g. rave.maccrab.com/rules/):
#   rules-manifest.json       {serial, corpus_version, min_maccrab_version?, rules:[...]}
#   rules-manifest.json.sig   raw Ed25519 signature over the manifest bytes
#
# Trust model (enforced by the CLIENT, not here): the manifest is verified
# against the bundled `rules.pub`; pushed rules are anti-rollback (monotonic
# serial), version-floored, additive-only (can't shadow a built-in/user id), and
# DETECTION-ONLY (never arm a response action). Keep the private key OFFLINE.
#
# Usage:
#   # one-time, on the keyholder's air-gapped machine:
#   scripts/build-rules-manifest.sh keygen ./rules.key ./rules.pub
#       → ship rules.pub into the app build; keep rules.key offline.
#
#   # each push:
#   scripts/build-rules-manifest.sh build \
#       --rules-dir ./pushed-rules \      # dir of NEW rule .yml files to distribute
#       --serial 1 \                      # MUST be > the last published serial
#       --key ./rules.key \
#       [--corpus 2026.06.27] [--min-version 1.20.0] \
#       --out ./dist/rules
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/maccrab-rulemanifest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- Ed25519 signer (CryptoKit — byte-identical to the client's verify) -------
build_signer() {
  cat > "$WORK/signer.swift" <<'SWIFT'
import Foundation
import CryptoKit
let a = CommandLine.arguments
func die(_ m: String) -> Never { FileHandle.standardError.write(Data((m+"\n").utf8)); exit(2) }
switch a.count >= 2 ? a[1] : "" {
case "keygen":
  guard a.count == 4 else { die("keygen <privOut> <pubOut>") }
  let k = Curve25519.Signing.PrivateKey()
  try! k.rawRepresentation.write(to: URL(fileURLWithPath: a[2]))          // 32-byte private
  try! k.publicKey.rawRepresentation.write(to: URL(fileURLWithPath: a[3])) // 32-byte rules.pub
case "sign":
  guard a.count == 5 else { die("sign <priv> <in> <sigOut>") }
  let p = try! Curve25519.Signing.PrivateKey(rawRepresentation: try! Data(contentsOf: URL(fileURLWithPath: a[2])))
  let m = try! Data(contentsOf: URL(fileURLWithPath: a[3]))
  try! p.signature(for: m).write(to: URL(fileURLWithPath: a[4]))           // 64-byte raw sig
default: die("usage: signer keygen|sign")
}
SWIFT
  swiftc -O "$WORK/signer.swift" -o "$WORK/signer" 2>"$WORK/signer.log" \
    || { echo "signer compile failed:"; cat "$WORK/signer.log"; exit 2; }
}

case "${1:-}" in
keygen)
  shift; [ $# -eq 2 ] || { echo "usage: $0 keygen <privOut> <pubOut>" >&2; exit 2; }
  build_signer
  "$WORK/signer" keygen "$1" "$2"
  chmod 600 "$1"
  echo "✓ private key → $1 (chmod 600 — keep OFFLINE, never commit)"
  echo "✓ public  key → $2 (32 bytes — bundle as the app's rules.pub)"
  ;;
build)
  shift
  RULES_DIR="" SERIAL="" KEY="" CORPUS="$(date +%Y.%m.%d)" MINVER="" OUT=""
  while [ $# -gt 0 ]; do case "$1" in
    --rules-dir) RULES_DIR="$2"; shift 2;;
    --serial) SERIAL="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --corpus) CORPUS="$2"; shift 2;;
    --min-version) MINVER="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac; done
  [ -d "$RULES_DIR" ] || { echo "ERROR: --rules-dir not a directory: $RULES_DIR" >&2; exit 2; }
  [ -n "$SERIAL" ] && [[ "$SERIAL" =~ ^[0-9]+$ ]] || { echo "ERROR: --serial must be a positive integer" >&2; exit 2; }
  [ -r "$KEY" ] || { echo "ERROR: --key not readable: $KEY" >&2; exit 2; }
  [ -n "$OUT" ] || { echo "ERROR: --out required" >&2; exit 2; }
  mkdir -p "$OUT"

  echo ">>> Compiling $RULES_DIR → JSON"
  python3 "$ROOT/Compiler/compile_rules.py" --input-dir "$RULES_DIR" --output-dir "$WORK/compiled" >/dev/null

  echo ">>> Assembling rules-manifest.json (serial=$SERIAL corpus=$CORPUS${MINVER:+ min=$MINVER})"
  python3 - "$WORK/compiled" "$SERIAL" "$CORPUS" "$MINVER" "$OUT/rules-manifest.json" <<'PY'
import sys, json, glob, os
compiled, serial, corpus, minver, out = sys.argv[1:6]
rules = []
for f in sorted(glob.glob(os.path.join(compiled, "**", "*.json"), recursive=True)):
    if os.path.basename(f) in ("manifest.json", ".bundle_version"): continue
    r = json.load(open(f))
    rid = r.get("id", "")
    if not rid or "/" in rid or "\\" in rid or rid == "..":
        sys.exit(f"refusing rule with unsafe id {rid!r} in {f}")
    rules.append(r)
if not rules:
    sys.exit("no compiled rules found — nothing to publish")
m = {"serial": int(serial), "corpus_version": corpus, "rules": rules}
if minver:
    m["min_maccrab_version"] = minver
json.dump(m, open(out, "w"), indent=2, sort_keys=True)
print(f"    {len(rules)} rule(s) inlined")
PY

  echo ">>> Signing"
  build_signer
  "$WORK/signer" sign "$KEY" "$OUT/rules-manifest.json" "$OUT/rules-manifest.json.sig"

  echo ""
  echo "✓ $OUT/rules-manifest.json"
  echo "✓ $OUT/rules-manifest.json.sig  (sha256: $(shasum -a 256 "$OUT/rules-manifest.json" | awk '{print $1}'))"
  echo ""
  echo "Publish BOTH files at the channel base URL, then verify a client sees it:"
  echo "  MACCRAB_RULES_BASE_URL=<base> maccrabctl rules check-updates"
  echo "Dry-run the full fetch+verify in isolation first:"
  echo "  scripts/test-rule-channel-e2e.sh   # (uses a throwaway key/server)"
  ;;
*)
  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
esac
