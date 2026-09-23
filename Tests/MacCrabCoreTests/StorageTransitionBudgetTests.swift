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
        #expect(storage.effectiveEventsFamilyMaxSizeMB == 376)
        #expect(storage.effectiveAlertsFamilyMaxSizeMB == 200)
        #expect(storage.configuredEventsAndAlertsTotalMaxSizeMB == 576)

        #expect(storage.effectiveEventsFamilyMaxSizeMB(
            legacyEvidenceTransitionReserveMiB: 0
        ) == 376)
        #expect(storage.effectiveEventsFamilyMaxSizeMB(
            legacyEvidenceTransitionReserveMiB: 37
        ) == 413)
        #expect(storage.effectiveEventsFamilyMaxSizeMB(
            legacyEvidenceTransitionReserveMiB: .max
        ) == 476)
        #expect(storage.configuredEventsAndAlertsTotalMaxSizeMB(
            legacyEvidenceTransitionReserveMiB: .max
        ) == 676)
        #expect(storage.configuredEventsAndAlertsTotalMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB: 137
        ) == 713)
        #expect(storage.configuredEventsAndAlertsTotalMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB: .max
        ) == .max)
    }

    private func transitionMeasurement(
        evidence: AlertEvidenceBudgetSnapshot,
        familyFootprintBytes: Int64,
        checkpointDrained: Bool = true,
        freelistCount: Int64 = 0,
        pageCount: Int64? = nil
    ) -> LegacyAlertEvidenceTransitionMeasurement {
        LegacyAlertEvidenceTransitionMeasurement(
            evidence: evidence,
            familyFootprintBytes: familyFootprintBytes,
            walCheckpointDrained: checkpointDrained,
            pageSizeBytes: 4_096,
            pageCount: pageCount ?? max(1, familyFootprintBytes / 4_096),
            freelistCount: freelistCount
        )
    }

    @Test("reserve shrink requires family below startup convergence target")
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
        #expect(measured.pendingReserveMiB == 18)
        #expect(measured.pendingReserveFitsHardBoundary == true)
        let applied = budget.commitPendingReserve(18, ticket: ticket)
        #expect(applied.reserveMiB == 18)
        #expect(applied.pendingReserveMiB == nil)

        let empty = AlertEvidenceBudgetSnapshot(
            rowCount: 0,
            logicalBytes: 0,
            allocatedBytes: 4_096,
            chargedBytes: 4_096,
            maxBytes: 100 * SQLitePersistentStorePolicy.bytesPerMiB
        )
        let steadyTarget = EventsSizeCapBoundary(
            maxSizeMiB: storage.effectiveEventsFamilyMaxSizeMB
        ).targetBytes
        // v1.22.2: the reserve may fall only as far as the main file shrank
        // since the previous measurement, so each drop to zero below needs the
        // full 18 MiB physically returned. The credit is spent per measurement:
        // a refused shrink does not carry it forward.
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let oneByteOver = budget.update(
            measurement: transitionMeasurement(
                evidence: empty,
                familyFootprintBytes: steadyTarget + 1,
                freelistCount: 1,
                pageCount: (exactBoundary - 18 * mib) / 4_096
            ),
            ticket: ticket
        )
        #expect(oneByteOver.reserveMiB == 18)
        #expect(oneByteOver.pendingReserveMiB == 0)
        #expect(oneByteOver.pendingReserveFitsHardBoundary == false)
        #expect(oneByteOver.freelistBytes == 4_096)
        #expect(oneByteOver.lastReclaimedBytes == 18 * mib)
        #expect(budget.commitPendingReserve(0, ticket: ticket).reserveMiB == 18)

        let exactSteadyBoundary = budget.update(
            measurement: transitionMeasurement(
                evidence: empty,
                familyFootprintBytes: steadyTarget,
                pageCount: (exactBoundary - 36 * mib) / 4_096
            ),
            ticket: ticket
        )
        #expect(exactSteadyBoundary.reserveMiB == 18)
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

        // The explicit 420 MiB envelope stays a 320 MiB family. Evidence
        // ownership rounds to 33 MiB, but this family is one byte over the
        // 400 MiB live cap's 296 MiB target, so it needs an 81 MiB reserve.
        // Evidence ownership alone cannot authorize the smaller live cap.
        let family = 296 * mib + 1
        let ticket = budget.measurementTicket()
        let measured = budget.update(
            measurement: transitionMeasurement(
                evidence: evidence,
                familyFootprintBytes: family
            ),
            ticket: ticket
        )
        #expect(measured.appliedReserveMiB == 100)
        #expect(measured.pendingReserveMiB == 81)
        #expect(measured.pendingReserveFitsHardBoundary == true)
        #expect(measured.proposedHardAdmissionBoundaryBytes == 401 * mib)
        #expect(EventsSizeCapBoundary(maxSizeMiB: 400).targetBytes < family)
        #expect(EventsSizeCapBoundary(maxSizeMiB: 401).targetBytes >= family)
        #expect(budget.commitPendingReserve(81, ticket: ticket).reserveMiB == 81)
    }

    @Test("an explicit small envelope cannot invent extra transition reserve")
    func insufficientCustomEnvelopeRemainsAuthoritative() {
        var storage = DaemonConfig.StorageConfig()
        storage.eventsMaxSizeMB = 420
        let budget = LegacyEvidenceTransitionBudget(storageConfig: storage)
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let family = 321 * mib + 1
        let evidence = AlertEvidenceBudgetSnapshot(
            rowCount: 11_651,
            logicalBytes: 21_386_393,
            allocatedBytes: 34_492_416,
            chargedBytes: 34_492_416,
            maxBytes: 100 * mib
        )
        let ticket = budget.measurementTicket()
        let measured = budget.update(
            measurement: transitionMeasurement(
                evidence: evidence,
                familyFootprintBytes: family
            ),
            ticket: ticket
        )
        #expect(budget.storageConfig().eventsMaxSizeMB == 420)
        #expect(budget.storageConfig().effectiveEventsFamilyMaxSizeMB == 320)
        #expect(measured.appliedReserveMiB == 100)
        #expect(measured.maximumReserveMiB == 100)
        #expect(measured.pendingReserveMiB == nil)
        #expect(EventsSizeCapBoundary(maxSizeMiB: 420).targetBytes < family)
        #expect(budget.commitPendingReserve(108, ticket: ticket).reserveMiB == 100)
    }

    @Test("installed retained family selects a startup-safe bounded reserve")
    func installedRetainedFamilyStartupBoundary() {
        let storage = DaemonConfig.StorageConfig().clampedToSafeFloors()
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
        // Exact compacted footprint from the disqualified rc.29 retained-store
        // probe. It cannot fit the evidence-only reserve's startup target.
        // A 60 MiB reserve is the smallest bounded value: the 436 MiB live cap
        // has a 328.4 MiB target, while 435 MiB permits only 327.5 MiB.
        let family: Int64 = 343_535_616
        let ticket = budget.measurementTicket()
        let measured = budget.update(
            measurement: transitionMeasurement(
                evidence: evidence,
                familyFootprintBytes: family
            ),
            ticket: ticket
        )

        #expect(measured.appliedReserveMiB == 100)
        #expect(measured.pendingReserveMiB == 60)
        #expect(measured.pendingReserveFitsHardBoundary == true)
        #expect(EventsSizeCapBoundary(maxSizeMiB: 435).targetBytes < family)
        #expect(EventsSizeCapBoundary(maxSizeMiB: 436).targetBytes >= family)
        #expect(budget.commitPendingReserve(60, ticket: ticket).reserveMiB == 60)
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

// MARK: - rc.37: a reader must not be able to stop the engine booting
//
// `SQLITE_CHECKPOINT_TRUNCATE` copies every WAL frame into the main database and
// then resets the file. The reset needs a moment with no readers and returns
// SQLITE_BUSY *without undoing the copy*. Boot required rc == SQLITE_OK, so an
// installed host that returned `busy=1, log=31225, checkpointed=31225` — every
// frame durable, only the truncate blocked — refused to start and relaunched
// every ~10s, each relaunch taking the lock the truncate needed. The dashboard
// holds exactly this kind of read transaction, so running the UI could stop the
// engine from starting.
//
// These exercise the decision directly rather than trying to provoke SQLite's
// locking race, which is not deterministic enough to assert on.
@Suite("rc.37 boot WAL drain decision")
struct BootWALDrainDecisionTests {

    @Test("The exact installed-host result counts as drained")
    func installedHostResultIsDrained() {
        // busy=1, log=31225, checkpointed=31225 — observed verbatim on the host
        // that could not boot.
        #expect(EventStore.walDrainSatisfied(
            resultCode: SQLITE_BUSY, logFrames: 31_225, checkpointedFrames: 31_225
        ))
    }

    @Test("A clean truncate is drained")
    func cleanTruncateIsDrained() {
        #expect(EventStore.walDrainSatisfied(
            resultCode: SQLITE_OK, logFrames: 0, checkpointedFrames: 0
        ))
        #expect(EventStore.walDrainSatisfied(
            resultCode: SQLITE_OK, logFrames: 128, checkpointedFrames: 128
        ))
    }

    @Test("A partial copy is NOT drained")
    func partialCopyIsNotDrained() {
        // This is the case the guard exists for: frames left un-checkpointed
        // means the main database is genuinely incomplete.
        #expect(!EventStore.walDrainSatisfied(
            resultCode: SQLITE_BUSY, logFrames: 31_225, checkpointedFrames: 12_000
        ))
        #expect(!EventStore.walDrainSatisfied(
            resultCode: SQLITE_BUSY, logFrames: 100, checkpointedFrames: 0
        ))
    }

    @Test("A hard error is never drained")
    func hardErrorIsNotDrained() {
        #expect(!EventStore.walDrainSatisfied(
            resultCode: SQLITE_CORRUPT, logFrames: 10, checkpointedFrames: 10
        ))
        #expect(!EventStore.walDrainSatisfied(
            resultCode: SQLITE_IOERR, logFrames: 0, checkpointedFrames: 0
        ))
    }
}

// MARK: - rc.37: a store that is merely too large must still boot
//
// Boot treated three conditions as one fatal predicate. Two are genuine
// unknown-state cases; the third — a proposed reserve that does not fit the hard
// boundary — is a CAPACITY condition. Retention, checkpointing and compaction
// all run only AFTER a successful boot, so a store that had merely outgrown its
// transition headroom could never be reduced: the engine exited, sysextd
// relaunched it ~10s later, and it exited again. An installed host logged 55
// relaunches in 90 minutes with protection entirely off and no operator-free
// route back.
@Suite("rc.37 legacy-evidence transition boot decision")
struct LegacyEvidenceBootDecisionTests {

    private func snapshot(
        measurementFailed: Bool = false,
        walDrained: Bool? = true,
        applied: Int = 0,
        pending: Int? = nil,
        pendingFits: Bool? = nil
    ) -> LegacyEvidenceTransitionBudgetSnapshot {
        LegacyEvidenceTransitionBudgetSnapshot(
            rowCount: 0,
            chargedBytes: 0,
            appliedReserveMiB: applied,
            pendingReserveMiB: pending,
            pendingReserveFitsHardBoundary: pendingFits,
            maximumReserveMiB: 100,
            measurementFailed: measurementFailed,
            familyFootprintBytes: 0,
            proposedHardAdmissionBoundaryBytes: nil,
            transactionReserveBytes: 32 * 1_048_576,
            walCheckpointDrained: walDrained,
            freelistBytes: 0,
            configurationGeneration: 1,
            staleMeasurementsDiscarded: 0,
            measuredAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
    }

    @Test("An oversized family degrades instead of refusing to boot")
    func oversizedFamilyDegrades() {
        // This is the installed-host case: the store outgrew its headroom.
        let decision = snapshot(applied: 70, pending: 100, pendingFits: false)
            .bootDecision
        #expect(decision == .degrade(
            reserveMiB: 70,
            reason: "proposed reserve 100 MiB does not fit the hard boundary"
        ))
        // It must fall back to the already-proven reserve, never adopt the one
        // that does not fit.
        #expect(decision.reserveMiB == 70)
    }

    @Test("A fitting reserve is adopted normally")
    func fittingReserveProceeds() {
        #expect(
            snapshot(applied: 70, pending: 100, pendingFits: true).bootDecision
                == .proceed(reserveMiB: 100)
        )
        #expect(
            snapshot(applied: 70).bootDecision == .proceed(reserveMiB: 70)
        )
    }

    @Test("Genuine unknown-state conditions still refuse to boot")
    func unknownStateStillFails() {
        // These must stay fail-closed: without a usable measurement or a drained
        // WAL the store cannot be reasoned about, and starting anyway risks
        // writing on top of state we do not understand.
        #expect(snapshot(measurementFailed: true).bootDecision
            == .fail(reason: "legacy-evidence transition measurement failed"))
        #expect(snapshot(walDrained: false).bootDecision
            == .fail(reason: "legacy-evidence transition WAL was not drained"))
        #expect(snapshot(walDrained: nil).bootDecision
            == .fail(reason: "legacy-evidence transition WAL was not drained"))
    }
}
