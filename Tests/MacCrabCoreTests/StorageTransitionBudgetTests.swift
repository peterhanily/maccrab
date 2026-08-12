import Foundation
import Testing
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Legacy alert-evidence transition budget")
struct StorageTransitionBudgetTests {
    @Test("steady-state total is unchanged and upgrade reserve is bounded")
    func configEnvelope() {
        let storage = DaemonConfig.StorageConfig().clampedToSafeFloors()
        #expect(storage.effectiveEventsFamilyMaxSizeMB == 340)
        #expect(storage.effectiveAlertsFamilyMaxSizeMB == 200)
        #expect(storage.configuredEventsAndAlertsTotalMaxSizeMB == 540)

        #expect(storage.effectiveEventsFamilyMaxSizeMB(
            legacyEvidenceTransitionReserveMiB: 0
        ) == 340)
        #expect(storage.effectiveEventsFamilyMaxSizeMB(
            legacyEvidenceTransitionReserveMiB: 37
        ) == 377)
        #expect(storage.effectiveEventsFamilyMaxSizeMB(
            legacyEvidenceTransitionReserveMiB: .max
        ) == 440)
        #expect(storage.configuredEventsAndAlertsTotalMaxSizeMB(
            legacyEvidenceTransitionReserveMiB: .max
        ) == 640)
        #expect(storage.configuredEventsAndAlertsTotalMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB: 137
        ) == 677)
        #expect(storage.configuredEventsAndAlertsTotalMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB: .max
        ) == .max)
    }

    private func transitionMeasurement(
        evidence: AlertEvidenceBudgetSnapshot,
        familyFootprintBytes: Int64,
        checkpointDrained: Bool = true,
        freelistCount: Int64 = 0
    ) -> LegacyAlertEvidenceTransitionMeasurement {
        LegacyAlertEvidenceTransitionMeasurement(
            evidence: evidence,
            familyFootprintBytes: familyFootprintBytes,
            walCheckpointDrained: checkpointDrained,
            pageSizeBytes: 4_096,
            pageCount: max(1, familyFootprintBytes / 4_096),
            freelistCount: freelistCount
        )
    }

    @Test("reserve shrink requires family plus transaction reserve below boundary")
    func failSafeAccounting() {
        let storage = DaemonConfig.StorageConfig().clampedToSafeFloors()
        let budget = LegacyEvidenceTransitionBudget(storageConfig: storage)
        #expect(budget.snapshot().reserveMiB == 100)
        #expect(budget.snapshot().measurementFailed)

        let partial = AlertEvidenceBudgetSnapshot(
            rowCount: 2,
            logicalBytes: 1,
            allocatedBytes: SQLitePersistentStorePolicy.bytesPerMiB + 1,
            chargedBytes: SQLitePersistentStorePolicy.bytesPerMiB + 1,
            maxBytes: 100 * SQLitePersistentStorePolicy.bytesPerMiB
        )
        let exactBoundary = Int64(290)
            * SQLitePersistentStorePolicy.bytesPerMiB
        let ticket = budget.measurementTicket()
        let measured = budget.update(
            measurement: transitionMeasurement(
                evidence: partial,
                familyFootprintBytes: exactBoundary
            ),
            ticket: ticket
        )
        #expect(measured.reserveMiB == 100)
        #expect(!measured.measurementFailed)
        #expect(measured.pendingReserveMiB == 2)
        #expect(measured.pendingReserveFitsHardBoundary == true)
        let appliedTwo = budget.commitPendingReserve(2, ticket: ticket)
        #expect(appliedTwo.reserveMiB == 2)
        #expect(appliedTwo.pendingReserveMiB == nil)

        let empty = AlertEvidenceBudgetSnapshot(
            rowCount: 0,
            logicalBytes: 0,
            allocatedBytes: 4_096,
            chargedBytes: 4_096,
            maxBytes: 100 * SQLitePersistentStorePolicy.bytesPerMiB
        )
        let oneByteOver = budget.update(
            measurement: transitionMeasurement(
                evidence: empty,
                familyFootprintBytes: 308
                    * SQLitePersistentStorePolicy.bytesPerMiB + 1,
                freelistCount: 1
            ),
            ticket: ticket
        )
        #expect(oneByteOver.reserveMiB == 2)
        #expect(oneByteOver.pendingReserveMiB == 0)
        #expect(oneByteOver.pendingReserveFitsHardBoundary == false)
        #expect(oneByteOver.freelistBytes == 4_096)
        #expect(budget.commitPendingReserve(0, ticket: ticket).reserveMiB == 2)

        let exactSteadyBoundary = budget.update(
            measurement: transitionMeasurement(
                evidence: empty,
                familyFootprintBytes: 308
                    * SQLitePersistentStorePolicy.bytesPerMiB
            ),
            ticket: ticket
        )
        #expect(exactSteadyBoundary.reserveMiB == 2)
        #expect(exactSteadyBoundary.pendingReserveMiB == 0)
        #expect(exactSteadyBoundary.pendingReserveFitsHardBoundary == true)
        #expect(budget.commitPendingReserve(0, ticket: ticket).reserveMiB == 0)

        let failed = budget.update(measurement: nil, ticket: ticket)
        #expect(failed.reserveMiB == 0)
        #expect(failed.pendingReserveMiB == 100)
        #expect(failed.pendingReserveFitsHardBoundary == true)
        #expect(failed.measurementFailed)
    }

    @Test("retained store reserve covers exact whole-family rounding")
    func retainedStoreWholeFamilyRounding() {
        var storage = DaemonConfig.StorageConfig().clampedToSafeFloors()
        storage.eventsMaxSizeMB = 420
        let budget = LegacyEvidenceTransitionBudget(storageConfig: storage)
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let charged: Int64 = 34_492_416
        let evidence = AlertEvidenceBudgetSnapshot(
            rowCount: 11_651,
            logicalBytes: 21_386_393,
            allocatedBytes: charged,
            chargedBytes: charged,
            maxBytes: 100 * mib
        )

        // Evidence ownership rounds to 33 MiB, but the installed family plus
        // the fixed transaction reserve is one byte above the 353-MiB
        // boundary.  The bounded transition must select 34 MiB rather than
        // crash-looping or granting the full 100-MiB allowance.
        let family = (320 + 33) * mib
            - SQLitePersistentStorePolicy.eventTransactionReserveBytes + 1
        let ticket = budget.measurementTicket()
        let measured = budget.update(
            measurement: transitionMeasurement(
                evidence: evidence,
                familyFootprintBytes: family
            ),
            ticket: ticket
        )
        #expect(measured.appliedReserveMiB == 100)
        #expect(measured.pendingReserveMiB == 34)
        #expect(measured.pendingReserveFitsHardBoundary == true)
        #expect(measured.proposedHardAdmissionBoundaryBytes == 354 * mib)
        #expect(budget.commitPendingReserve(34, ticket: ticket).reserveMiB == 34)
    }

    @Test("stale sweep cannot overwrite a newer storage config generation")
    func reloadSweepRace() {
        let storage = DaemonConfig.StorageConfig().clampedToSafeFloors()
        let budget = LegacyEvidenceTransitionBudget(storageConfig: storage)
        let staleTicket = budget.measurementTicket()

        var reloaded = storage
        reloaded.eventsHotTierMinutes += 1
        let currentTicket = budget.installStorageConfig(reloaded)
        #expect(currentTicket.configurationGeneration
            == staleTicket.configurationGeneration + 1)

        let empty = AlertEvidenceBudgetSnapshot(
            rowCount: 0,
            logicalBytes: 0,
            allocatedBytes: 0,
            chargedBytes: 0,
            maxBytes: 100 * SQLitePersistentStorePolicy.bytesPerMiB
        )
        let measurement = transitionMeasurement(
            evidence: empty,
            familyFootprintBytes: 1 * SQLitePersistentStorePolicy.bytesPerMiB
        )
        let stale = budget.update(
            measurement: measurement,
            ticket: staleTicket
        )
        #expect(stale.reserveMiB == 100)
        #expect(stale.staleMeasurementsDiscarded == 1)

        let current = budget.update(
            measurement: measurement,
            ticket: currentTicket
        )
        #expect(current.reserveMiB == 100)
        #expect(current.pendingReserveMiB == 0)
        #expect(current.pendingReserveFitsHardBoundary == true)
        #expect(budget.commitPendingReserve(
            0,
            ticket: currentTicket
        ).reserveMiB == 0)
        #expect(budget.storageConfig() == reloaded)
    }

    @Test("upgrade fixture measures populated legacy evidence and empties to zero")
    func populatedUpgradeFixture() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-legacy-transition-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }

        let store = try EventStore(directory: directory.path)
        let timestamp = Date()
        let process = ProcessInfo(
            pid: 4_242,
            ppid: 1,
            rpid: 1,
            name: "fixture",
            executable: "/usr/bin/fixture",
            commandLine: "/usr/bin/fixture",
            args: [],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "fixture",
            groupId: 20,
            startTime: timestamp,
            ancestors: [],
            isPlatformBinary: false
        )
        let event = Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process
        )
        try await store.insert(event: event)
        try await store.recordAlertEvidence(
            alertId: "upgrade-alert",
            alertTimestamp: timestamp.addingTimeInterval(1),
            windowSeconds: 30,
            maxRows: 50
        )

        let cap = 100 * SQLitePersistentStorePolicy.bytesPerMiB
        let populated = try await store.legacyAlertEvidenceTransitionMeasurement(
            maxBytes: cap
        )
        #expect(populated.evidence.rowCount == 1)
        #expect(populated.evidence.chargedBytes > 0)
        #expect(populated.familyFootprintBytes > 0)
        #expect(populated.walCheckpointDrained)

        #expect(try await store.deleteEvidence(alertId: "upgrade-alert") == 1)
        let empty = try await store.legacyAlertEvidenceTransitionMeasurement(
            maxBytes: cap
        )
        #expect(empty.evidence.rowCount == 0)
        #expect(empty.evidence.chargedBytes == 0)
    }

    @Test("a real pinned WAL reader keeps the lower reserve pending")
    func pinnedReaderKeepsPending() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-transition-pin-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }

        let store = try EventStore(directory: directory.path)
        let timestamp = Date()
        let process = ProcessInfo(
            pid: 9_001,
            ppid: 1,
            rpid: 1,
            name: "pin-fixture",
            executable: "/usr/bin/pin-fixture",
            commandLine: "/usr/bin/pin-fixture",
            args: [],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "fixture",
            groupId: 20,
            startTime: timestamp,
            ancestors: [],
            isPlatformBinary: false
        )
        try await store.insert(event: Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process
        ))
        #expect(await store.walCheckpointTruncate())

        let path = directory.appendingPathComponent("events.db").path
        var reader: OpaquePointer?
        #expect(sqlite3_open_v2(
            path,
            &reader,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK)
        guard let reader else { return }
        defer { sqlite3_close(reader) }
        #expect(sqlite3_exec(reader, "BEGIN", nil, nil, nil) == SQLITE_OK)
        var statement: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            reader,
            "SELECT COUNT(*) FROM events",
            -1,
            &statement,
            nil
        ) == SQLITE_OK)
        guard let statement else { return }
        defer {
            sqlite3_finalize(statement)
            sqlite3_exec(reader, "ROLLBACK", nil, nil, nil)
        }
        #expect(sqlite3_step(statement) == SQLITE_ROW)

        for offset in 1...8 {
            try await store.insert(event: Event(
                timestamp: timestamp.addingTimeInterval(Double(offset)),
                eventCategory: .process,
                eventType: .start,
                eventAction: "exec",
                process: process
            ))
        }

        let measured = try await store
            .legacyAlertEvidenceTransitionMeasurement(
                maxBytes: 100 * SQLitePersistentStorePolicy.bytesPerMiB
            )
        #expect(!measured.walCheckpointDrained)

        let storage = DaemonConfig.StorageConfig().clampedToSafeFloors()
        let budget = LegacyEvidenceTransitionBudget(storageConfig: storage)
        let pending = budget.update(
            measurement: measured,
            ticket: budget.measurementTicket()
        )
        #expect(pending.reserveMiB == 100)
        #expect(pending.pendingReserveMiB == 0)
        #expect(pending.pendingReserveFitsHardBoundary == false)
        #expect(pending.walCheckpointDrained == false)
    }
}
