// CSQLCipherInitGate — process-wide lock serializing the
// sqlite3_open + PRAGMA key + initial schema-migration window
// across every SQLCipher consumer in MacCrabForensics.
//
// History: v1.13.0-rc.1 shipped ArtifactStore with no such lock.
// Under heavier parallel test load (v1.13.0-rc.6 → rc.7 boundary)
// we saw sporadic SQLITE_MISUSE (21) on subsequent prepare()
// calls. The first fix added a static NSLock inside ArtifactStore
// itself. v1.16.0-rc.18 extracts the lock to a shared gate so
// LiveDBSnapshot (which opens its own raw sqlite3 handles) gets
// the same serialization — re-enabling the 3 LiveDBSnapshot
// tests that v1.13.0-rc.5 / rc.7 / rc.9 had to mark
// @Test(.disabled).
//
// The lock is held ONLY through the open window. Per-connection
// thread safety is handled by SQLITE_OPEN_FULLMUTEX as before.

import Foundation

public enum CSQLCipherInitGate {

    /// Shared lock. Reentrant guard is unnecessary — callers must
    /// not nest sqlite3_open across this gate.
    private static let lock = NSLock()

    /// Hold the gate while `body` executes (open + PRAGMA key +
    /// initial PRAGMAs + first prepare).
    public static func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    /// Async variant — same lock, but the body is `async`.
    public static func withLock<T>(_ body: () async throws -> T) async rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try await body()
    }
}
