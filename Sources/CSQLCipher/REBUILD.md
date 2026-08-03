# Rebuilding the CSQLCipher Amalgamation

This directory holds the vendored SQLCipher amalgamation that MacCrab links against. It is **the only SQLite implementation in the codebase** — no target depends on the macOS-bundled `/usr/lib/libsqlite3.dylib`. SQLCipher in non-codec mode (i.e. when no `PRAGMA key` is issued) behaves identically to upstream SQLite, so existing un-encrypted stores (`events.db`, `alerts.db`, etc.) continue to work transparently.

## Why vendor?

- **Symbol collision avoidance.** Linking both system libsqlite3 and CSQLCipher into the same binary produces duplicate-symbol errors. Vendoring + migrating everything is cleaner than per-call-site renames.
- **Version control.** macOS bundles a moving target (currently ~3.43 on macOS 15.x). CSQLCipher 4.16.0 ships SQLite 3.53.1; bumps are deliberate.
- **Encryption availability.** Any store can opt into SQLCipher encryption by issuing `PRAGMA key` at open time; the API is already linked.

## How to bump SQLCipher

When upgrading to a newer SQLCipher release (e.g. v4.17.0):

1. **Clone, authenticate, and detach at the exact release commit.** Never
   build from a mutable branch or from a tag name whose peeled commit has not
   been recorded first:

   ```bash
   cd /private/tmp
   git clone https://github.com/sqlcipher/sqlcipher.git
   cd sqlcipher
   expected_tag=v4.17.0       # whatever the new release tag is
   expected_commit=<40-hex peeled commit reviewed from the upstream release>
   test "$(git rev-parse "${expected_tag}^{commit}")" = "$expected_commit"
   git checkout --detach "$expected_commit"
   test "$(git rev-parse HEAD)" = "$expected_commit"
   git status --porcelain=v1  # must print nothing
   ```

   Record the exact repository, tag, peeled commit, SQLCipher version, bundled
   SQLite version/source id, and final file digests in `PROVENANCE`. The
   currently blessed `v4.16.0` tag peels to
   `e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc`.

2. **Verify the upstream checkout before building, then build the amalgamation
   with CommonCrypto:**

   ```bash
   make verify-source
   ./configure CFLAGS="-DSQLITE_HAS_CODEC -DSQLCIPHER_CRYPTO_CC -DSQLITE_TEMP_STORE=2" \
               LDFLAGS="-framework Security -framework Foundation"
   make sqlite3.c
   make sqlite3.h
   ```

   The `configure` script uses SQLCipher's bundled autosetup (pure tcl) — no autoconf needed.

3. **Copy the resulting files into the repo:**
   ```bash
   cp sqlite3.c <repo>/Sources/CSQLCipher/sqlite3.c
   cp sqlite3.h <repo>/Sources/CSQLCipher/include/sqlite3.h
   ```

4. **Update `PROVENANCE` and `VERSION`.** Compute the copied-file digests from
   inside the MacCrab checkout, not the upstream worktree:

   ```bash
   shasum -a 256 Sources/CSQLCipher/sqlite3.c \
       Sources/CSQLCipher/include/sqlite3.h
   ```

   Copy those exact values into `PROVENANCE` and `VERSION`, along with the
   detached upstream commit and the `SQLITE_VERSION`, `SQLITE_SOURCE_ID`, and
   `CIPHER_VERSION_NUMBER` values in the generated files.

5. **Run the deterministic provenance guard, then the full test suite** against
   the new amalgamation:

   ```bash
   ./scripts/check-sqlcipher-provenance.sh
   ./scripts/test-sqlcipher-provenance.sh
   swift test
   ```

   The guard fails when either vendored file, its version/source macros, the
   exact upstream commit, or this rebuild workflow drifts from the checked
   manifest. SQLite has strong backward compatibility; any test failure still
   needs investigation before merging.

6. **Review the manifest and vendored-file diff together.** Never update a
   digest merely to silence the guard: independently confirm the upstream tag,
   peeled commit, build inputs, and generated version/source-id first.

## Compile flags (set via Package.swift `cSettings`)

| Flag | Why |
|---|---|
| `SQLITE_HAS_CODEC` | Enables SQLCipher's codec hooks; mandatory for `PRAGMA key`. |
| `SQLCIPHER_CRYPTO_CC` | Crypto backend = Apple CommonCrypto. No OpenSSL dependency. |
| `SQLITE_TEMP_STORE=2` | Temp tables live in memory only — no temp files on disk that could leak case data. |
| `SQLITE_THREADSAFE=1` | Serialized threading mode. Matches the macOS bundled libsqlite3 default. |
| `SQLITE_ENABLE_FTS5` | Required for `artifact_fts5_<content_type>` per plan §3.4. |
| `SQLITE_ENABLE_RTREE` | Defensive enable; some collectors may want geographic indexing. |
| `SQLITE_DEFAULT_FOREIGN_KEYS=1` | Enforce FKs by default (the plan's `artifact_data → artifacts(id)` reference relies on this). |
| `SQLITE_ENABLE_BYTECODE_VTAB` | Query plan inspection (`EXPLAIN`). |
| `SQLITE_ENABLE_DBSTAT_VTAB` | Per-table size accounting — useful for `case show` artifact byte totals. |
| `SQLITE_DQS=0` | Deny double-quoted strings as identifiers. SQLite's recommended anti-foot-gun. |
| `SQLITE_STRICT_SUBTYPE=1` | Strict subtype checking. |
| `HAVE_USLEEP=1` | Use `usleep()` for sub-second delays. macOS supports it. |

## Linker frameworks

- `Security.framework` — for `SecRandomCopyBytes` (used as the RNG when CommonCrypto isn't seeded).
- `Foundation.framework` — for the Apple platform abstractions the amalgamation expects.

CommonCrypto itself is part of `libSystem` and links automatically.

## What is NOT vendored

- SQLCipher's `sqlcipher` shell program (interactive REPL) — not used at runtime.
- SQLCipher's TCL bindings — not used.
- The OpenSSL crypto backend — `SQLCIPHER_CRYPTO_CC` selects CommonCrypto instead.

Only the single-file amalgamation (`sqlite3.c` + `sqlite3.h`) is in the tree.
