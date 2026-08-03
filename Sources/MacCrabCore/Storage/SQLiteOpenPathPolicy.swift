import CSQLCipher

/// The single path-based SQLite open boundary used by production Swift code.
///
/// `SQLITE_OPEN_NOFOLLOW` rejects a symbolic link in any path component. macOS
/// deliberately exposes `/var` and `/tmp` as root-owned aliases into
/// `/private`, so those two complete leading components are expanded
/// lexically before the flag is applied. No other component is resolved or
/// accepted as an alias.
///
/// This closes symlink traversal at SQLite's actual open rather than relying
/// on a racy pathname preflight. It does not make an arbitrary writable parent
/// directory safe from non-symlink replacement; persistent production stores
/// still rely on their owner-controlled support-directory boundary (and their
/// family metadata checks) for that part of the contract.
///
/// Production callers pass filesystem databases, so relative paths, SQLite
/// URI filenames, `:memory:`, and embedded NULs fail closed. `/etc` is not an
/// accepted alias: a database beneath that macOS symlink is rejected by
/// NOFOLLOW unless the caller supplies its explicit `/private/etc` path.
public enum SQLiteOpenPathPolicy {
    public static func normalizedPath(_ path: String) -> String {
        if path == "/var" || path.hasPrefix("/var/") {
            return "/private" + path
        }
        if path == "/tmp" || path.hasPrefix("/tmp/") {
            return "/private" + path
        }
        return path
    }

    @discardableResult
    public static func open(
        _ displayPath: String,
        database: UnsafeMutablePointer<OpaquePointer?>,
        flags: Int32,
        vfs: UnsafePointer<CChar>? = nil
    ) -> Int32 {
        guard displayPath.first == "/",
              !displayPath.utf8.contains(0) else {
            return SQLITE_CANTOPEN
        }
        return sqlite3_open_v2(
            normalizedPath(displayPath),
            database,
            flags | SQLITE_OPEN_NOFOLLOW,
            vfs
        )
    }
}
