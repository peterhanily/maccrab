// CorruptBackupAndAuditRotationTests.swift
//
// v1.21.4 reliability/hygiene fixes:
//
//   C-03: init-time DB corruption recovery drops `*.corrupt-<ts>` backups
//         (events.db / alerts.db siblings; tracegraph quarantine copies) but
//         nothing pruned them. `DaemonSetup.pruneCorruptBackups` now keeps the
//         N most-recent corruption events per DB.
//
//   G-04: `dashboard_audit.log` was plain-appended with no cap.
//         `DaemonTimers.rotateAuditLogIfNeeded` now rotates it at a size cap,
//         keeping a bounded number of generations.

import Testing
import Foundation
import Darwin
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Startup SQLite quarantine authorization")
struct StartupSQLiteQuarantineAuthorizationTests {
    private struct InjectedMoveFailure: Error {}

    private func makeFamily(base: String = "evidence.db") throws -> URL {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("MacCrabStartupRecovery-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        for member in CorruptDBFamilyMember.allCases {
            try Data("original:\(member.rawValue)".utf8).write(
                to: directory.appendingPathComponent(base + member.rawValue)
            )
        }
        return directory
    }

    private func expectFamilyIntact(
        _ directory: URL,
        base: String = "evidence.db"
    ) throws {
        for member in CorruptDBFamilyMember.allCases {
            let source = directory.appendingPathComponent(base + member.rawValue)
            #expect(FileManager.default.fileExists(atPath: source.path))
            #expect(try Data(contentsOf: source) == Data("original:\(member.rawValue)".utf8))
        }
        let entries = try FileManager.default.contentsOfDirectory(
            atPath: directory.path
        )
        #expect(!entries.contains { $0.contains(".corrupt-") })
    }

    @Test("BUSY, PERM, READONLY, IOERR, and untyped failures preserve DB/WAL/SHM")
    func nonCorruptionNeverMovesEvidence() throws {
        let directory = try makeFamily()
        defer { try? FileManager.default.removeItem(at: directory) }
        let failures: [any Error] = [
            EventStoreError.sqliteFailure(
                context: "open", message: "busy",
                resultCode: SQLITE_BUSY,
                extendedResultCode: SQLITE_BUSY,
                systemErrno: 0
            ),
            EventStoreError.sqliteFailure(
                context: "open", message: "permission",
                resultCode: SQLITE_PERM,
                extendedResultCode: SQLITE_PERM,
                systemErrno: EPERM
            ),
            AlertStoreError.sqliteFailure(
                context: "open", message: "read-only",
                resultCode: SQLITE_READONLY,
                extendedResultCode: SQLITE_READONLY,
                systemErrno: EROFS
            ),
            CausalGraphStoreError.sqliteFailure(
                context: "open", message: "I/O",
                resultCode: SQLITE_IOERR,
                extendedResultCode: SQLITE_IOERR | Int32(3 << 8),
                systemErrno: EIO
            ),
            // A corruption-looking string without captured SQLite result codes
            // must never authorize evidence movement.
            EventStoreError.databaseOpenFailed(
                "database disk image is malformed"
            ),
        ]

        for failure in failures {
            #expect(throws: DaemonSetup.DatabaseQuarantineAuthorizationError.self) {
                try DaemonSetup.quarantineExplicitSQLiteCorruption(
                    directory: directory.path,
                    base: "evidence.db",
                    error: failure,
                    timestamp: 1_700_000_010
                )
            }
            try expectFamilyIntact(directory)
        }
    }

    @Test("atomic move failure surfaces and rolls the whole family back")
    func atomicFailureSurfacesWithoutFreshDBWindow() throws {
        let directory = try makeFamily()
        defer { try? FileManager.default.removeItem(at: directory) }
        let corruption = CausalGraphStoreError.sqliteFailure(
            context: "schema",
            message: "corrupt",
            resultCode: SQLITE_CORRUPT,
            extendedResultCode: SQLITE_CORRUPT,
            systemErrno: 0
        )

        #expect(throws: CorruptDBBackupError.self) {
            try DaemonSetup.quarantineExplicitSQLiteCorruption(
                directory: directory.path,
                base: "evidence.db",
                error: corruption,
                timestamp: 1_700_000_011,
                moveOperation: { move, phase in
                    if phase == .quarantine, move.member == .shm {
                        throw InjectedMoveFailure()
                    }
                    try FileManager.default.moveItem(
                        atPath: move.source,
                        toPath: move.destination
                    )
                }
            )
        }
        try expectFamilyIntact(directory)
    }

    @Test("all three production startup owners use the typed atomic boundary")
    func productionOwnersCannotDriftToBlanketQuarantine() throws {
        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Sources/MacCrabAgentKit/DaemonSetup.swift"),
            encoding: .utf8
        )
        let boundaryUses = source.components(
            separatedBy: "quarantineExplicitSQLiteCorruption("
        ).count - 1
        #expect(boundaryUses == 4,
                "one declaration plus EventStore, AlertStore, and TraceGraph owners")
        #expect(source.contains("CorruptDBBackup.quarantineAtomically("))
        #expect(!source.contains("CorruptDBBackup.backup("),
                "the deprecated failure-swallowing quarantine shim must stay unreachable")
        #expect(!source.contains("try? FileManager.default.moveItem(atPath: src"),
                "TraceGraph must not return to partial best-effort family moves")
    }
}

@Suite("C-03: corrupt-backup retention sweep")
struct CorruptBackupPruneTests {

    private func makeTempDir() -> String {
        let dir = NSTemporaryDirectory() + "MacCrabCorrupt-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    private func touch(_ dir: String, _ name: String) {
        FileManager.default.createFile(atPath: dir + "/" + name, contents: Data("x".utf8))
    }

    private func names(_ dir: String) -> Set<String> {
        Set((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [])
    }

    @Test("keeps only the N most-recent corruption events, with all sidecars")
    func keepsNewestN() {
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        // Five corruption events (ascending timestamps), each with its main
        // file plus a -wal sidecar, in the backupCorruptDatabase name shape.
        for ts in [1000, 2000, 3000, 4000, 5000] {
            touch(dir, "events.db.corrupt-\(ts)")
            touch(dir, "events.db-wal.corrupt-\(ts)")
        }

        DaemonSetup.pruneCorruptBackups(directory: dir, base: "events.db", keep: 3)

        let remaining = names(dir)
        // Newest three stamps survive (main + sidecar each = 6 files).
        for ts in [3000, 4000, 5000] {
            #expect(remaining.contains("events.db.corrupt-\(ts)"))
            #expect(remaining.contains("events.db-wal.corrupt-\(ts)"))
        }
        // Oldest two stamps are gone entirely.
        for ts in [1000, 2000] {
            #expect(!remaining.contains("events.db.corrupt-\(ts)"))
            #expect(!remaining.contains("events.db-wal.corrupt-\(ts)"))
        }
        #expect(remaining.count == 6)
    }

    @Test("leaves live DB files and a different DB's backups untouched")
    func doesNotTouchUnrelated() {
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        touch(dir, "events.db")               // live file — no `.corrupt-`
        touch(dir, "events.db-wal")           // live sidecar
        touch(dir, "alerts.db.corrupt-9999")  // different base — out of scope
        for ts in [10, 20, 30, 40] { touch(dir, "events.db.corrupt-\(ts)") }

        DaemonSetup.pruneCorruptBackups(directory: dir, base: "events.db", keep: 2)

        let remaining = names(dir)
        #expect(remaining.contains("events.db"))
        #expect(remaining.contains("events.db-wal"))
        #expect(remaining.contains("alerts.db.corrupt-9999"))
        #expect(remaining.contains("events.db.corrupt-40"))
        #expect(remaining.contains("events.db.corrupt-30"))
        #expect(!remaining.contains("events.db.corrupt-20"))
        #expect(!remaining.contains("events.db.corrupt-10"))
    }

    @Test("parses the tracegraph quarantine name shape (ts before the sidecar)")
    func tracegraphNameShape() {
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        // openCausalStore writes `tracegraph.db.corrupt-<ts><ext>`.
        for ts in [100, 200, 300] {
            touch(dir, "tracegraph.db.corrupt-\(ts)")
            touch(dir, "tracegraph.db.corrupt-\(ts)-wal")
        }

        DaemonSetup.pruneCorruptBackups(directory: dir, base: "tracegraph.db", keep: 1)

        let remaining = names(dir)
        #expect(remaining == ["tracegraph.db.corrupt-300", "tracegraph.db.corrupt-300-wal"])
    }
}

@Suite("G-04: dashboard_audit.log size rotation")
struct AuditLogRotationTests {

    private func makeTempDir() -> String {
        let dir = NSTemporaryDirectory() + "MacCrabAudit-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test("over-cap file rotates to .1 and the live path is cleared")
    func rotatesOverCap() {
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/dashboard_audit.log"
        try? Data(repeating: 0x41, count: 200).write(to: URL(fileURLWithPath: path))

        DaemonTimers.rotateAuditLogIfNeeded(path: path, maxBytes: 100, maxArchives: 3)

        #expect(!FileManager.default.fileExists(atPath: path))
        #expect(FileManager.default.fileExists(atPath: path + ".1"))
    }

    @Test("under-cap file is left in place")
    func leavesUnderCap() {
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/dashboard_audit.log"
        try? Data(repeating: 0x41, count: 50).write(to: URL(fileURLWithPath: path))

        DaemonTimers.rotateAuditLogIfNeeded(path: path, maxBytes: 100, maxArchives: 3)

        #expect(FileManager.default.fileExists(atPath: path))
        #expect(!FileManager.default.fileExists(atPath: path + ".1"))
    }

    @Test("repeated rotations keep at most maxArchives generations")
    func boundedGenerations() {
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/dashboard_audit.log"
        let fm = FileManager.default

        // Simulate the caller loop: fresh over-cap live file, then rotate.
        for _ in 0..<6 {
            try? Data(repeating: 0x41, count: 200).write(to: URL(fileURLWithPath: path))
            DaemonTimers.rotateAuditLogIfNeeded(path: path, maxBytes: 100, maxArchives: 3)
        }

        #expect(fm.fileExists(atPath: path + ".1"))
        #expect(fm.fileExists(atPath: path + ".2"))
        #expect(fm.fileExists(atPath: path + ".3"))
        #expect(!fm.fileExists(atPath: path + ".4"))  // oldest falls off the end
    }
}
