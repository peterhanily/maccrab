import Testing
import Foundation
import Darwin
@testable import MacCrabCore

@Suite("EventStore complete producer admission reprobe")
struct EventStoreProducerReprobeTests {
    private let mib: Int64 = 1_048_576
    private let reserve: Int64 = 32 * 1_048_576
    private let cap: Int64 = 320 * 1_048_576
    private let floor: Int64 = 1_024 * 1_048_576

    private final class Measurements: @unchecked Sendable {
        private let lock = NSLock()
        private var footprint: Int64 = 0
        private var freeSpace: Int64 = Int64.max
        private var successfulReadsBeforeFailure: Int?
        private var failure: SQLitePersistentStoreAdmissionError?

        func set(footprint: Int64, freeSpace: Int64 = Int64.max) {
            lock.lock()
            defer { lock.unlock() }
            self.footprint = footprint
            self.freeSpace = freeSpace
            successfulReadsBeforeFailure = nil
            failure = nil
        }

        func failFootprint(
            afterSuccessfulReads count: Int,
            with failure: SQLitePersistentStoreAdmissionError
        ) {
            lock.lock()
            defer { lock.unlock() }
            successfulReadsBeforeFailure = count
            self.failure = failure
        }

        func readFootprint() throws -> Int64 {
            lock.lock()
            defer { lock.unlock() }
            if let remaining = successfulReadsBeforeFailure {
                if remaining == 0, let failure { throw failure }
                successfulReadsBeforeFailure = max(0, remaining - 1)
            }
            return footprint
        }

        func readFreeSpace() -> Int64 {
            lock.lock()
            defer { lock.unlock() }
            return freeSpace
        }
    }

    private func fixture(transactionReserve: Int64? = nil) async throws -> (
        directory: URL, store: EventStore, measurements: Measurements
    ) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("event-producer-reprobe-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        do {
            let store = try EventStore(
                path: directory.appendingPathComponent("events.db").path,
                storagePolicy: SQLitePersistentStorePolicy(
                    maxFootprintBytes: cap,
                    freeSpaceFloorBytes: floor,
                    transactionReserveBytes: transactionReserve ?? reserve,
                    storageVolumePath: directory.path
                )
            )
            let measurements = Measurements()
            try await store.setStorageAdmissionProbesForTesting(
                footprint: { _ in try measurements.readFootprint() },
                freeSpace: { _ in measurements.readFreeSpace() }
            )
            return (directory, store, measurements)
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    @Test("File proof keeps both transaction reserves and does not latch priority closed")
    func fileBoundaryAndLaneIsolation() async throws {
        let (directory, store, measurements) = try await fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let priorityReserve = EventStore.priorityLaneReserveBytes(
            maxFootprintBytes: cap
        )
        let boundary = cap - 2 * reserve - priorityReserve
        #expect(boundary == 224 * mib)
        measurements.set(footprint: boundary, freeSpace: floor + 2 * reserve)
        let before = try await store.storageAdmissionConnectionStateForTesting()
        let rows = try await store.count()

        let exact = try await store.reprobeStorageAdmissionForWrite(lane: .file)
        #expect(exact.footprintBytes == boundary)
        #expect(exact.freeSpaceBytes == floor + 2 * reserve)
        #expect(exact.latchedFailure == nil)

        measurements.set(footprint: boundary + 1)
        do {
            _ = try await store.reprobeStorageAdmissionForWrite(lane: .file)
            Issue.record("File proof accepted one byte beyond its complete boundary")
        } catch let error as SQLitePersistentStoreAdmissionError {
            #expect(error == .footprintLimit(
                footprintBytes: boundary + 1,
                reserveBytes: 2 * reserve + priorityReserve,
                maxFootprintBytes: cap
            ))
        }
        let afterRefusal = try await store.storageAdmissionConnectionStateForTesting()
        #expect(!afterRefusal.inTransaction)
        #expect(afterRefusal.totalChanges == before.totalChanges)
        #expect(await store.storageAdmissionSnapshot()?.latchedFailure == nil)

        // A file-only refusal must leave this same connection usable by the
        // priority lane; its protected space is the point of the lane reserve.
        let priority = try await store.reprobeStorageAdmissionForWrite(lane: .priority)
        #expect(priority.footprintBytes == boundary + 1)
        measurements.set(footprint: boundary)
        _ = try await store.reprobeStorageAdmissionForWrite(lane: .file)
        let after = try await store.storageAdmissionConnectionStateForTesting()
        #expect(!after.inTransaction)
        #expect(after.totalChanges == before.totalChanges)
        #expect(try await store.count() == rows)
    }

    @Test("Priority proof includes terminal headroom and rolls back shared pressure")
    func priorityBoundaryAndRecovery() async throws {
        let (directory, store, measurements) = try await fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let boundary = cap - 2 * reserve
        measurements.set(footprint: boundary)
        let before = try await store.storageAdmissionConnectionStateForTesting()
        let rows = try await store.count()
        let exact = try await store.reprobeStorageAdmissionForWrite(lane: .priority)
        #expect(exact.footprintBytes == boundary)

        measurements.set(footprint: boundary + 1)
        do {
            _ = try await store.reprobeStorageAdmissionForWrite(lane: .priority)
            Issue.record("Priority proof omitted its post-commit reserve")
        } catch let error as SQLitePersistentStoreAdmissionError {
            #expect(error == .footprintLimit(
                footprintBytes: boundary + 1,
                reserveBytes: 2 * reserve,
                maxFootprintBytes: cap
            ))
        }
        let refused = try await store.storageAdmissionConnectionStateForTesting()
        #expect(!refused.inTransaction)
        #expect(refused.totalChanges == before.totalChanges)
        #expect(await store.storageAdmissionSnapshot()?.latchedFailure != nil)

        // The ordinary preliminary gate still owns pressure recovery and may
        // reopen the connection, returning to actual private-file probes.
        measurements.set(footprint: 0)
        let recovered = try await store.reprobeStorageAdmissionForWrite(lane: .priority)
        #expect(recovered.latchedFailure == nil)
        #expect(try await store.count() == rows)
        let recoveredState = try await store.storageAdmissionConnectionStateForTesting()
        #expect(!recoveredState.inTransaction)
    }

    @Test("Producer free-space proof requires the floor plus both reserves")
    func completeFreeSpaceRequirement() async throws {
        let (directory, store, measurements) = try await fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let requiredFree = floor + 2 * reserve
        measurements.set(footprint: 0, freeSpace: requiredFree)
        let before = try await store.storageAdmissionConnectionStateForTesting()
        let exact = try await store.reprobeStorageAdmissionForWrite(lane: .file)
        #expect(exact.freeSpaceBytes == requiredFree)

        measurements.set(footprint: 0, freeSpace: requiredFree - 1)
        do {
            _ = try await store.reprobeStorageAdmissionForWrite(lane: .priority)
            Issue.record("Producer proof admitted less than floor plus two reserves")
        } catch let error as SQLitePersistentStoreAdmissionError {
            #expect(error == .lowFreeSpace(
                freeBytes: requiredFree - 1,
                floorBytes: floor,
                reserveBytes: 2 * reserve,
                requiredFreeBytes: requiredFree
            ))
        }
        let after = try await store.storageAdmissionConnectionStateForTesting()
        #expect(!after.inTransaction)
        #expect(after.totalChanges == before.totalChanges)
        #expect(try await store.count() == 0)
    }

    @Test("Serialized measurement failure retains its cause and releases the writer lock")
    func serializedProbeFailureRetainsCause() async throws {
        let (directory, store, measurements) = try await fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let before = try await store.storageAdmissionConnectionStateForTesting()
        let failure = SQLitePersistentStoreAdmissionError.familyProbeFailed(
            path: directory.appendingPathComponent("events.db").path,
            systemErrno: EIO
        )
        // The ordinary preflight succeeds; the next authoritative read takes
        // place after BEGIN IMMEDIATE. No store contents are changed.
        measurements.failFootprint(afterSuccessfulReads: 1, with: failure)
        do {
            _ = try await store.reprobeStorageAdmissionForWrite(lane: .priority)
            Issue.record("Serialized measurement failure was suppressed")
        } catch let error as SQLitePersistentStoreAdmissionError {
            #expect(error == failure)
        }
        let after = try await store.storageAdmissionConnectionStateForTesting()
        #expect(!after.inTransaction)
        #expect(after.totalChanges == before.totalChanges)

        measurements.set(footprint: 0)
        _ = try await store.reprobeStorageAdmissionForWrite(lane: .file)
        #expect(try await store.count() == 0)
    }

    @Test("An undersized custom reserve reports the actual protected headroom")
    func undersizedReserveReportsProtectedRequirement() async throws {
        let undersizedReserve = 16 * mib
        let (directory, store, measurements) = try await fixture(
            transactionReserve: undersizedReserve
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        measurements.set(footprint: 0)
        let before = try await store.storageAdmissionConnectionStateForTesting()

        // A smaller policy cannot contain the fixed terminal-settlement
        // requirement. The guard must identify that excessive requirement,
        // rather than report the base estimate, which equals its own bound.
        do {
            _ = try await store.reprobeStorageAdmissionForWrite(lane: .priority)
            Issue.record("Unsupported reserve bypassed terminal-settlement protection")
        } catch let error as SQLitePersistentStoreAdmissionError {
            switch error {
            case .transactionEstimateExceedsReserve(let estimated, let bound):
                #expect(estimated > bound)
                #expect(bound == undersizedReserve)
            default:
                Issue.record("Unexpected admission failure: \(error)")
            }
        }
        let after = try await store.storageAdmissionConnectionStateForTesting()
        #expect(!after.inTransaction)
        #expect(after.totalChanges == before.totalChanges)
        #expect(try await store.count() == 0)
    }
}
