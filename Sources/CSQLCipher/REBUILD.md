# Rebuilding the CSQLCipher Amalgamation

This directory holds the vendored SQLCipher amalgamation that MacCrab links against. It is **the only SQLite implementation in the codebase** — no target depends on the macOS-bundled `/usr/lib/libsqlite3.dylib`. SQLCipher in non-codec mode (i.e. when no `PRAGMA key` is issued) behaves identically to upstream SQLite, so existing un-encrypted stores (`events.db`, `alerts.db`, etc.) continue to work transparently.

## Why vendor?

- **Symbol collision avoidance.** Linking both system libsqlite3 and CSQLCipher into the same binary produces duplicate-symbol errors. Vendoring + migrating everything is cleaner than per-call-site renames.
- **Version control.** macOS bundles a moving target (currently ~3.43 on macOS 15.x). CSQLCipher 4.16.0 ships SQLite 3.53.1; bumps are deliberate.
- **Encryption availability.** Any store can opt into SQLCipher encryption by issuing `PRAGMA key` at open time; the API is already linked.

## How to bump SQLCipher

When upgrading to a newer SQLCipher release (e.g. v4.17.0):

1. **Clone and check out the new release tag:**
   ```bash
   cd /tmp
   git clone https://github.com/sqlcipher/sqlcipher.git
   cd sqlcipher
   git checkout v4.17.0    # whatever the new tag is
   ```

2. **Build the amalgamation with CommonCrypto:**
   ```bash
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

4. **Update this directory's `VERSION` file** with the new SQLCipher + SQLite versions and build date.

5. **Run the full test suite** (`swift test`) against the new amalgamation. SQLite has strong backward compatibility; minor version bumps almost always pass, but any failures should be investigated before merging.

6. **Tag the bump commit** so future-Peter (or `git blame`) can trace which SQLCipher release the codebase is on at any point.

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
