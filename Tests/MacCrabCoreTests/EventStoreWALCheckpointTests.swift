// EventStoreWALCheckpointTests.swift
//
// rc.13 WAL tests exercise bounded journal transactions without retaining a
// large `[Event]` query result. Exact scalar cardinality proves that every
// canonical record landed, while the physical SQLite-family measurements pin
// both the WAL limit and the configured family cap.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("EventStore: WAL bound, family cap, and TRUNCATE reclaim")
struct EventStoreWALCheckpointTests {
    private static let alphabet = Array(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            .utf8
    )

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("wal-ckpt-\(UUID().uuidString).db").path
    }

    private static func cleanup(_ path: String) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(atPath: path + suffix)
        }
    }

    private static func policy(for path: String) -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            maxFootprintBytes: 192 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes:
                SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: URL(fileURLWithPath: path)
                .deletingLastPathComponent().path
        )
    }

    private static func walSize(_ path: String) -> Int64 {
        let attributes = try? FileManager.default.attributesOfItem(
            atPath: path + "-wal"
        )
        return (attributes?[.size] as? NSNumber)?.int64Value ?? 0
    }

    /// Deterministic, printable data with no long repeated runs. Each seed
    /// produces a different stream so compression cannot turn the complete
    /// multi-block fixture into a tiny dictionary reference.
    private static func text(seed: UInt64, count: Int) -> String {
        var state = seed | 1
        var bytes: [UInt8] = []
        bytes.reserveCapacity(count)
        for _ in 0..<count {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            bytes.append(alphabet[Int((state >> 58) & 63)])
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func makeEvent(index: Int, fieldBytes: Int) -> Event {
        let commandLine = text(
            seed: UInt64(index &* 2 + 1),
            count: fieldBytes
        )
        let argument = text(
            seed: UInt64(index &* 2 + 2),
            count: fieldBytes
        )
        let process = MacCrabCore.ProcessInfo(
            pid: Int32(4_000 + index),
            ppid: 100,
            rpid: Int32(4_000 + index),
            name: "wal-fixture-\(index)",
            executable: "/usr/bin/wal-fixture",
            commandLine: commandLine,
            args: [argument],
            workingDirectory: "/Users/tester/project",
            userId: 501,
            userName: "tester",
            groupId: 20,
            startTime: Date(),
            ancestors: [],
            architecture: "arm64",
            isPlatformBinary: false
        )
        return Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process
        )
    }

    @Test("WAL and SQLite family stay bounded across more than 64 MiB canonical churn")
    func walAndFamilyStayBoundedUnderBurst() async throws {
        let path = Self.tempPath()
        defer { Self.cleanup(path) }
        let policy = Self.policy(for: path)
        let store = try EventStore(path: path, storagePolicy: policy)
        let admissionStart = Date()

        // 128 records with two independent 280 KiB fields encode more than
        // 70 MiB of canonical content. Sixteen-record transactions remain well
        // inside the fixed 32 MiB transaction reserve.
        let total = 128
        let batchSize = 16
        let fieldBytes = 280 * 1024
        var peakWAL: Int64 = 0
        var index = 0
        while index < total {
            let upper = min(index + batchSize, total)
            let batch = (index..<upper).map {
                Self.makeEvent(index: $0, fieldBytes: fieldBytes)
            }
            _ = try await store.insert(events: batch, lane: .priority)
            index = upper

            let wal = Self.walSize(path)
            let family = try SQLitePersistentStoreAdmission.measureFamily(path)
            peakWAL = max(peakWAL, wal)
            #expect(
                wal < StoragePragmas.journalSizeLimitBytes,
                "events.db-wal exceeded journal_size_limit after a committed batch"
            )
            #expect(
                family <= policy.maxFootprintBytes,
                "SQLite family exceeded its configured physical cap"
            )
        }

        #expect(peakWAL > 0, "fixture produced no WAL activity")
        #expect(try await store.count() == total)
        #expect(try await store.maintenanceRetainedRecordCount() == total)

        // Even very old source timestamps or size pressure cannot remove a
        // block before the durable admission-time retention floor.
        #expect(
            try await store.expireJournalBlocks(
                retainedThrough: admissionStart.addingTimeInterval(
                    EventStore.journalRetentionSeconds - 1
                ),
                maximumBlocks: 4_096
            ) == 0
        )
        #expect(try await store.count() == total)
    }

    @Test("walCheckpointTruncate reclaims WAL without changing exact cardinality")
    func truncateReclaimsWAL() async throws {
        let path = Self.tempPath()
        defer { Self.cleanup(path) }
        let policy = Self.policy(for: path)
        let store = try EventStore(path: path, storagePolicy: policy)

        let total = 64
        let batch = (0..<total).map {
            Self.makeEvent(index: $0, fieldBytes: 64 * 1024)
        }
        _ = try await store.insert(events: batch, lane: .priority)

        let before = Self.walSize(path)
        #expect(before > 0, "expected a non-empty WAL before truncate")
        #expect(
            try SQLitePersistentStoreAdmission.measureFamily(path)
                <= policy.maxFootprintBytes
        )

        #expect(await store.walCheckpointTruncate())
        let after = Self.walSize(path)
        #expect(after < before)
        #expect(after < 64 * 1024)

        #expect(try await store.count() == total)
        #expect(try await store.maintenanceRetainedRecordCount() == total)
        #expect(
            try SQLitePersistentStoreAdmission.measureFamily(path)
                <= policy.maxFootprintBytes
        )
    }
}
