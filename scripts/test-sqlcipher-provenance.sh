#!/bin/bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

"$SCRIPT_DIR/check-sqlcipher-provenance.sh" >/dev/null

TMP_ROOT=$(/usr/bin/mktemp -d /private/tmp/maccrab-sqlcipher-provenance.XXXXXX)
trap '/bin/rm -rf "$TMP_ROOT"' EXIT
/bin/mkdir -p "$TMP_ROOT/repo/scripts" "$TMP_ROOT/repo/Sources/CSQLCipher/include"
/bin/cp "$SCRIPT_DIR/check-sqlcipher-provenance.sh" "$TMP_ROOT/repo/scripts/"
/bin/cp "$PROJECT_DIR/Sources/CSQLCipher/PROVENANCE" \
    "$PROJECT_DIR/Sources/CSQLCipher/VERSION" \
    "$PROJECT_DIR/Sources/CSQLCipher/REBUILD.md" \
    "$PROJECT_DIR/Sources/CSQLCipher/sqlite3.c" \
    "$TMP_ROOT/repo/Sources/CSQLCipher/"
/bin/cp "$PROJECT_DIR/Sources/CSQLCipher/include/sqlite3.h" "$TMP_ROOT/repo/Sources/CSQLCipher/include/"

printf '\n/* fixture tamper */\n' >> "$TMP_ROOT/repo/Sources/CSQLCipher/sqlite3.c"
if "$TMP_ROOT/repo/scripts/check-sqlcipher-provenance.sh" >"$TMP_ROOT/out" 2>&1; then
    echo "ERROR: modified sqlite3.c passed provenance guard" >&2
    exit 1
fi
/usr/bin/grep -q 'sqlite3.c drifted' "$TMP_ROOT/out"

echo "PASS: SQLCipher provenance accepts blessed sources and rejects vendored drift"
