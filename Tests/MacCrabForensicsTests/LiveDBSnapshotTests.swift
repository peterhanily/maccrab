// LiveDBSnapshot tests — exercise the SQLite backup API path
// against a synthesized active DB. Verifies that the snapshot is:
//   - byte-readable from the resulting path
//   - sha256-named
//   - dedup-safe (re-snapshotting identical content reuses the file)

import Foundation
import CSQLCipher
import Testing
@testable import MacCrabForensics

@Suite("LiveDBSnapshot")
struct LiveDBSnapshotTests {

    private func makeLayout() -> CaseDirectoryLayout {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-snap-\(UUID().uuidString)")
        let layout = CaseDirectoryLayout(casesRoot: root, caseID: "snap-case")
        try? layout.createDirectoryStructure()
        return layout
    }

    private func makeSourceDB(at path: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open_v2(
            path, &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK, let h = db else {
            throw NSError(domain: "test", code: 1)
        }
        defer { sqlite3_close(h) }
        _ = sqlite3_exec(h, "CREATE TABLE access (service TEXT, client TEXT, auth_value INT, last_modified INT)", nil, nil, nil)
        _ = sqlite3_exec(h, """
            INSERT INTO access VALUES ('kTCCServiceMicrophone', 'com.test.app', 2, 700000000);
            INSERT INTO access VALUES ('kTCCServiceAccessibility', 'com.test.spy', 2, 700100000);
            """, nil, nil, nil)
    }

    @Test("Snapshot produces a sha256-named file under snapshots/")
    func snapshotProducesFile() throws {
        let layout = makeLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }
        let sourcePath = NSTemporaryDirectory() + "test-source-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: sourcePath) }
        try makeSourceDB(at: sourcePath)

        let result = try LiveDBSnapshot.snapshot(sourcePath: sourcePath, layout: layout)
        #expect(FileManager.default.fileExists(atPath: result.path.path))
        #expect(result.sha256.count == 64)
        #expect(result.path.lastPathComponent == "\(result.sha256).db")
        #expect(result.sizeBytes > 0)
    }

    @Test("Snapshot is parsable read-only as a normal SQLite DB")
    func snapshotIsParsable() throws {
        let layout = makeLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }
        let sourcePath = NSTemporaryDirectory() + "test-parsable-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: sourcePath) }
        try makeSourceDB(at: sourcePath)

        let result = try LiveDBSnapshot.snapshot(sourcePath: sourcePath, layout: layout)

        // Open snapshot read-only and count rows.
        var db: OpaquePointer?
        let rc = sqlite3_open_v2(
            result.path.path, &db,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        )
        defer { if let h = db { sqlite3_close(h) } }
        #expect(rc == SQLITE_OK)
        guard let h = db else { return }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        sqlite3_prepare_v2(h, "SELECT COUNT(*) FROM access", -1, &stmt, nil)
        sqlite3_step(stmt)
        let count = sqlite3_column_int(stmt, 0)
        #expect(count == 2)
    }

    @Test("Snapshotting unchanged source twice dedupes via sha256 filename")
    func snapshotDedups() throws {
        let layout = makeLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }
        let sourcePath = NSTemporaryDirectory() + "test-dedup-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: sourcePath) }
        try makeSourceDB(at: sourcePath)

        let first = try LiveDBSnapshot.snapshot(sourcePath: sourcePath, layout: layout)
        let second = try LiveDBSnapshot.snapshot(sourcePath: sourcePath, layout: layout)
        // Same content → same sha → same file.
        #expect(first.sha256 == second.sha256)
        #expect(first.path.path == second.path.path)
    }

    @Test("Snapshotting a missing source throws sourceMissing")
    func snapshotMissingSource() {
        let layout = makeLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }
        #expect(throws: LiveDBSnapshotError.self) {
            _ = try LiveDBSnapshot.snapshot(
                sourcePath: "/var/empty/no-such-db.sqlite",
                layout: layout
            )
        }
    }
}
