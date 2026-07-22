// WalFootprintTests.swift
// v1.21.5 (RCA — pinned-WAL back-off): pins measureWalMB, the helper the
// size-cap sweep uses to tell a reclaimable free-page overage (fix with VACUUM)
// apart from a reader-pinned WAL (VACUUM cannot fix — back off instead).

import Testing
import Foundation
@testable import MacCrabAgentKit

@Suite("Storage: WAL footprint measurement")
struct WalFootprintTests {

    @Test("measureWalMB returns the -wal sidecar size, 0 when absent")
    func walSize() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("walmb-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = dir.appendingPathComponent("events.db").path

        // No -wal file yet → 0 (honest absent, never a fabricated value).
        #expect(measureWalMB(dbPath: db) == 0)

        // A 3 MB -wal sidecar → 3 MB (10^6-per-MB, matching measureDatabaseFootprintMB).
        let wal = db + "-wal"
        FileManager.default.createFile(atPath: wal, contents: Data(count: 3_000_000))
        #expect(measureWalMB(dbPath: db) == 3)

        // A 512 MB-class sidecar (the pinned-WAL case) reads as > 64 (the pin
        // threshold) — the size-cap sweep would back off rather than VACUUM.
        FileManager.default.createFile(atPath: wal, contents: Data(count: 130_000_000))
        #expect(measureWalMB(dbPath: db) == 130)
        #expect(measureWalMB(dbPath: db) > 64)
    }
}
