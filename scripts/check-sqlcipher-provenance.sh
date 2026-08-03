#!/bin/bash
# Deterministic drift guard for the vendored SQLCipher amalgamation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ROOT="$PROJECT_DIR/Sources/CSQLCipher"
PROVENANCE="$ROOT/PROVENANCE"

fail() { echo "ERROR: CSQLCipher provenance: $*" >&2; exit 1; }
[[ -f "$PROVENANCE" && ! -L "$PROVENANCE" ]] || fail "missing or linked PROVENANCE manifest"

keys=(format_version upstream_repository upstream_tag upstream_commit sqlcipher_version sqlite_version sqlite_source_id sqlite3_c_sha256 sqlite3_h_sha256)
while IFS='=' read -r key _; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    allowed=0
    for expected in "${keys[@]}"; do [[ "$key" == "$expected" ]] && allowed=1; done
    [[ "$allowed" == "1" ]] || fail "unknown manifest key: $key"
done < "$PROVENANCE"

value() {
    local key="$1" count
    count=$(/usr/bin/grep -c "^${key}=" "$PROVENANCE" || true)
    [[ "$count" == "1" ]] || fail "$key occurs $count times"
    /usr/bin/sed -n "s/^${key}=//p" "$PROVENANCE"
}
for key in "${keys[@]}"; do value "$key" >/dev/null; done

[[ "$(value format_version)" == "1" ]] || fail "unsupported manifest format"
[[ "$(value upstream_repository)" == "https://github.com/sqlcipher/sqlcipher" ]] || fail "unexpected upstream repository"
[[ "$(value upstream_tag)" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "bad upstream tag"
[[ "$(value upstream_commit)" =~ ^[a-f0-9]{40}$ ]] || fail "bad upstream commit"
[[ "$(value sqlite3_c_sha256)" =~ ^[a-f0-9]{64}$ ]] || fail "bad sqlite3.c digest"
[[ "$(value sqlite3_h_sha256)" =~ ^[a-f0-9]{64}$ ]] || fail "bad sqlite3.h digest"

actual_c=$(/usr/bin/shasum -a 256 "$ROOT/sqlite3.c" | /usr/bin/awk '{print $1}')
actual_h=$(/usr/bin/shasum -a 256 "$ROOT/include/sqlite3.h" | /usr/bin/awk '{print $1}')
[[ "$actual_c" == "$(value sqlite3_c_sha256)" ]] || fail "sqlite3.c drifted (got $actual_c)"
[[ "$actual_h" == "$(value sqlite3_h_sha256)" ]] || fail "sqlite3.h drifted (got $actual_h)"

c_sqlite=$(/usr/bin/sed -nE 's/^#define SQLITE_VERSION[[:space:]]+"([^"]+)"/\1/p' "$ROOT/sqlite3.c" | /usr/bin/head -1)
h_sqlite=$(/usr/bin/sed -nE 's/^#define SQLITE_VERSION[[:space:]]+"([^"]+)"/\1/p' "$ROOT/include/sqlite3.h" | /usr/bin/head -1)
c_source=$(/usr/bin/sed -nE 's/^#define SQLITE_SOURCE_ID[[:space:]]+"[^ ]+ [^ ]+ ([^"]+)"/\1/p' "$ROOT/sqlite3.c" | /usr/bin/head -1)
h_source=$(/usr/bin/sed -nE 's/^#define SQLITE_SOURCE_ID[[:space:]]+"[^ ]+ [^ ]+ ([^"]+)"/\1/p' "$ROOT/include/sqlite3.h" | /usr/bin/head -1)
c_cipher=$(/usr/bin/sed -nE 's/^#define CIPHER_VERSION_NUMBER[[:space:]]+([^[:space:]]+)/\1/p' "$ROOT/sqlite3.c" | /usr/bin/head -1)

[[ "$c_sqlite" == "$h_sqlite" && "$c_sqlite" == "$(value sqlite_version)" ]] || fail "SQLite version macro/manifest drift"
[[ "$c_source" == "$h_source" && "$c_source" == "$(value sqlite_source_id)" ]] || fail "SQLite source-id macro/manifest drift"
[[ "$c_cipher" == "$(value sqlcipher_version)" ]] || fail "SQLCipher version macro/manifest drift"

/usr/bin/grep -q "$(value upstream_commit)" "$ROOT/VERSION" || fail "VERSION omits exact upstream commit"
/usr/bin/grep -q 'PROVENANCE' "$ROOT/REBUILD.md" || fail "REBUILD.md omits checked provenance workflow"

echo "CSQLCipher $(value sqlcipher_version) provenance and vendored hashes verified"
