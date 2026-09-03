import Foundation
import Testing
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Alerts family admission-boundary recovery")
struct AlertsSizeCapRecoveryTests {
    private func tempDirectory() throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(
                "maccrab-alert-family-recovery-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )
        return url
    }

    private func makeAlert(_ index: Int) -> Alert {
        Alert(
            id: "alert-\(index)",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(index)),
            ruleId: "test.alert-family",
            ruleTitle: "Alert family recovery \(index)",
            severity: .high,
            eventId: "event-\(index)",
            description: String(repeating: "e", count: 512)
        )
    }

    /// Create end-of-file freelist pages without assigning them to alerts or
    /// alert_evidence. This models the allocator/page overhead that placed the
    /// installed family inside `(cap - reserve, cap]` while both DBSTAT owners
    /// remained below their independent sub-caps.
    private func addFreelistPadding(
        databasePath: String,
        bytes: Int
    ) throws {
        var handle: OpaquePointer?
        guard sqlite3_open_v2(
            databasePath,
            &handle,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK, let db = handle else {
            sqlite3_close(handle)
            throw FixtureError.sqlite
        }
        defer { sqlite3_close(db) }

        for sql in [
            "PRAGMA busy_timeout = 5000",
            "CREATE TABLE cap_dead_zone_padding (payload BLOB NOT NULL)",
            "INSERT INTO cap_dead_zone_padding VALUES (zeroblob(\(bytes)))",
            "DROP TABLE cap_dead_zone_padding",
            "PRAGMA wal_checkpoint(TRUNCATE)",
        ] {
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
                throw FixtureError.sqlite
            }
        }
    }

    private enum FixtureError: Error {
        case sqlite
    }

    private enum ProbeFixtureError: LocalizedError {
        case blocked

        var errorDescription: String? {
            "fixture ordinary admission remains blocked"
        }
    }

    private actor RecoveryLoopFixture {
        private(set) var maintenancePasses = 0
        private(set) var reprobes = 0
        private var footprint: Int64
        private let decrementBytes: Int64
        private let maintenanceResult:
            PreIngestionStorageMaintenanceResult
        private let succeedsOnPass: Int?
        private let transientPinPasses: Int

        init(
            footprint: Int64,
            decrementBytes: Int64,
            didRun: Bool = true,
            maintenanceResult:
                PreIngestionStorageMaintenanceResult? = nil,
            succeedsOnPass: Int? = nil,
            transientPinPasses: Int = 0
        ) {
            self.footprint = footprint
            self.decrementBytes = decrementBytes
            self.maintenanceResult = maintenanceResult
                ?? (didRun ? .ran : .didNotRun)
            self.succeedsOnPass = succeedsOnPass
            self.transientPinPasses = max(0, transientPinPasses)
        }

        func measure() -> Int64 { footprint }

        func maintain() -> PreIngestionStorageMaintenanceResult {
            maintenancePasses += 1
            if maintenancePasses <= transientPinPasses {
                return .transientlyPinned
            }
            if maintenanceResult == .ran {
                footprint = max(0, footprint - decrementBytes)
            }
            return maintenanceResult
        }

        func reprobe() throws {
            reprobes += 1
            guard let succeedsOnPass,
                  maintenancePasses >= succeedsOnPass else {
                throw ProbeFixtureError.blocked
            }
        }
    }

    @Test("cap minus reserve is the exact alert write boundary")
    func exactBoundaryArithmetic() {
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let boundary = AlertsSizeCapBoundary(
            nominalCapBytes: 200 * mib,
            transactionReserveBytes: 8 * mib
        )

        #expect(boundary.nominalCapBytes == 200 * mib)
        #expect(boundary.hardAdmissionBoundaryBytes == 192 * mib)
        #expect(boundary.recoveryTargetBytes == 184 * mib)
        #expect(!boundary.requiresMaintenance(
            footprintBytes: boundary.hardAdmissionBoundaryBytes
        ))
        #expect(boundary.requiresMaintenance(
            footprintBytes: boundary.hardAdmissionBoundaryBytes + 1
        ))
        #expect(boundary.requiresMaintenance(
            footprintBytes: boundary.nominalCapBytes
        ))
        #expect(!boundary.requiresStartupConvergence(
            footprintBytes: boundary.recoveryTargetBytes
        ))
        #expect(boundary.requiresStartupConvergence(
            footprintBytes: boundary.recoveryTargetBytes + 1
        ))
        #expect(boundary.recoveryTargetBytes + 1
            <= boundary.hardAdmissionBoundaryBytes,
                "target+1 is writable but lacks the startup durability margin")
    }

    @Test("setup awaits alert recovery before every ingestion producer")
    func startupRecoveryPrecedesIngestion() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let timers = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonTimers.swift"
            ),
            encoding: .utf8
        )
        let setup = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonSetup.swift"
            ),
            encoding: .utf8
        )
        let recovery = try #require(setup.range(of:
            "let alertStartupRecovery = await recoverAlertStoreBeforeProducers("
        ))
        let guardReady = try #require(setup.range(of:
            "guard alertStartupRecovery.writableBeforeProducers else"
        ))
        let finalProbe = try #require(setup.range(of:
            "reprobeAlertStoreAtActivationBoundary("
        ))
        let graphProof = try #require(setup.range(of:
            "causalStoreStartupRecovery = activationProof"
        ))
        let firstProducer = try #require(setup.range(of:
            "label: \"deception-deploy\""
        ))
        #expect(recovery.lowerBound < guardReady.lowerBound)
        #expect(guardReady.lowerBound < firstProducer.lowerBound)
        #expect(guardReady.lowerBound < finalProbe.lowerBound)
        #expect(finalProbe.lowerBound < graphProof.lowerBound)
        #expect(graphProof.lowerBound < firstProducer.lowerBound)
        #expect(timers.contains(
            "alertsSizeCapTimer.schedule(deadline: .now() + 3600, repeating: 3600)"
        ))
        #expect(timers.contains("await enforceAlertsSizeCapNow(state: state)"))
        #expect(!timers.contains(
            "alertsSizeCapTimer.schedule(deadline: .now() + 1800"
        ))
        let helperStart = try #require(timers.range(of:
            "func recoverAlertStoreBeforeProducers("
        ))
        let helperEnd = try #require(timers.range(
            of: "// MARK: - On-demand sweep entry point",
            range: helperStart.upperBound..<timers.endIndex
        ))
        let helper = timers[helperStart.lowerBound..<helperEnd.lowerBound]
        let pinPreflight = try #require(helper.range(of:
            "alertStore.walCheckpointTruncate()"
        ))
        let destructiveEnforcer = try #require(helper.range(of:
            "enforceAlertsSizeCap("
        ))
        #expect(pinPreflight.lowerBound < destructiveEnforcer.lowerBound,
                "startup must detect a reader pin before pruning alert parents")
        #expect(helper.contains("forceConvergenceToTarget: true"))
        #expect(helper.contains("boundary.requiresStartupConvergence("))
        #expect(timers.contains(
            "boundaryBytes: boundary.recoveryTargetBytes"
        ))
    }

    @Test("startup recovery ignores ran=true until the third normal reprobe succeeds")
    func boundedRecoveryRequiresOrdinaryAdmission() async {
        let fixture = RecoveryLoopFixture(
            footprint: 300,
            decrementBytes: 50,
            succeedsOnPass: 3
        )
        let result = await runBoundedPreIngestionStorageRecovery(
            component: "fixture",
            maximumPasses: 6,
            measureFootprint: { await fixture.measure() },
            maintenance: { await fixture.maintain() },
            reprobeOrdinaryAdmission: { try await fixture.reprobe() }
        )

        #expect(result.writableBeforeProducers)
        #expect(result.passes == 3)
        #expect(result.lastFootprintBytes == 150)
        #expect(await fixture.maintenancePasses == 3)
        #expect(await fixture.reprobes == 3)
    }

    @Test("startup recovery stops on no progress or a skipped helper")
    func boundedRecoveryStopsWhenNonconverged() async {
        let stalled = RecoveryLoopFixture(
            footprint: 300,
            decrementBytes: 0
        )
        let noProgress = await runBoundedPreIngestionStorageRecovery(
            component: "stalled",
            maximumPasses: 6,
            measureFootprint: { await stalled.measure() },
            maintenance: { await stalled.maintain() },
            reprobeOrdinaryAdmission: { try await stalled.reprobe() }
        )
        #expect(!noProgress.writableBeforeProducers)
        #expect(noProgress.passes == 1)
        #expect(noProgress.reason.contains("no physical family progress"))
        #expect(noProgress.lastProbeError?.contains("remains blocked") == true)

        let skipped = RecoveryLoopFixture(
            footprint: 300,
            decrementBytes: 50,
            didRun: false
        )
        let didNotRun = await runBoundedPreIngestionStorageRecovery(
            component: "skipped",
            maximumPasses: 6,
            measureFootprint: { await skipped.measure() },
            maintenance: { await skipped.maintain() },
            reprobeOrdinaryAdmission: { try await skipped.reprobe() }
        )
        #expect(!didNotRun.writableBeforeProducers)
        #expect(didNotRun.passes == 1)
        #expect(didNotRun.reason.contains("maintenance helper did not run"))
    }

    @Test("reader-pin grace retries without repeating any deletion")
    func boundedRecoveryGivesPinnedReaderNoDeleteGrace() async {
        let pinned = RecoveryLoopFixture(
            footprint: 300,
            decrementBytes: 50,
            maintenanceResult: .transientlyPinned
        )
        let result = await runBoundedPreIngestionStorageRecovery(
            component: "pinned",
            maximumPasses: 6,
            maximumPinnedRetries: 3,
            pinnedRetryDelayNanoseconds: 0,
            measureFootprint: { await pinned.measure() },
            maintenance: { await pinned.maintain() },
            reprobeOrdinaryAdmission: { try await pinned.reprobe() }
        )

        #expect(!result.writableBeforeProducers)
        #expect(result.passes == 3)
        #expect(result.lastFootprintBytes == 300)
        #expect(result.reason.contains(
            "reader-pinned pre-maintenance checkpoint"
        ))
        #expect(await pinned.measure() == 300,
                "a pinned preflight must never enter the deletion path")
        #expect(await pinned.maintenancePasses == 3)
        #expect(await pinned.reprobes == 3)
    }

    @Test("reader-pin grace converges when a dashboard snapshot releases")
    func boundedRecoveryOutwaitsReleasedReaderWithoutDeletingDuringPin() async {
        let pinned = RecoveryLoopFixture(
            footprint: 300,
            decrementBytes: 50,
            succeedsOnPass: 5,
            transientPinPasses: 4
        )
        let result = await runBoundedPreIngestionStorageRecovery(
            component: "released-reader",
            maximumPasses: 6,
            maximumPinnedRetries: 5,
            pinnedRetryDelayNanoseconds: 0,
            measureFootprint: { await pinned.measure() },
            maintenance: { await pinned.maintain() },
            reprobeOrdinaryAdmission: { try await pinned.reprobe() }
        )

        #expect(result.writableBeforeProducers)
        #expect(result.passes == 5)
        #expect(result.lastFootprintBytes == 250,
                "only the post-release maintenance pass may reclaim bytes")
        #expect(await pinned.maintenancePasses == 5)
        #expect(await pinned.reprobes == 5)
    }

    @Test("post-maintenance reader pin is not misclassified as no progress")
    func boundedRecoveryRetriesPostMaintenanceReaderPin() async {
        let pinned = RecoveryLoopFixture(
            footprint: 600,
            decrementBytes: 0,
            maintenanceResult: .ranThenTransientlyPinned
        )
        let result = await runBoundedPreIngestionStorageRecovery(
            component: "post-maintenance-pin",
            maximumPasses: 4,
            maximumPinnedRetries: 3,
            pinnedRetryDelayNanoseconds: 0,
            measureFootprint: { await pinned.measure() },
            maintenance: { await pinned.maintain() },
            reprobeOrdinaryAdmission: { try await pinned.reprobe() }
        )

        #expect(!result.writableBeforeProducers)
        #expect(result.passes == 3)
        #expect(result.reason.contains("post-maintenance checkpoint"))
        #expect(!result.reason.contains("no physical family progress"))
    }

    @Test("startup operation retries busy but never permanent storage failure")
    func startupOperationRetriesOnlyTypedBusy() async throws {
        let busy = RecoveryLoopFixture(
            footprint: 0,
            decrementBytes: 0,
            succeedsOnPass: 3
        )
        let value: Int = try await retryTransientEventStoreStartupOperation(
            maximumAttempts: 4,
            retryDelayNanoseconds: 0,
            operation: {
                let attempt = await busy.maintain()
                _ = attempt
                do {
                    try await busy.reprobe()
                    return 42
                } catch {
                    throw EventStoreError.busy("fixture reader pin")
                }
            }
        )
        #expect(value == 42)
        #expect(await busy.maintenancePasses == 3)

        var permanentAttempts = 0
        do {
            let _: Int = try await retryTransientEventStoreStartupOperation(
                maximumAttempts: 4,
                retryDelayNanoseconds: 0,
                operation: {
                    permanentAttempts += 1
                    throw EventStoreError.storageNotReady("fixture permanent")
                }
            )
            Issue.record("permanent startup failure unexpectedly succeeded")
        } catch let error as EventStoreError {
            guard case .storageNotReady = error else {
                Issue.record("wrong permanent error: \(error)")
                return
            }
        }
        #expect(permanentAttempts == 1)
    }

    @Test("startup reclaims the writable target-to-hard interval")
    func startupForcesRecoveryTargetHeadroom() async throws {
        let directory = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let reserve = 8 * mib
        let databasePath = directory.appendingPathComponent("alerts.db").path
        let store = try AlertStore(
            directory: directory.path,
            storagePolicy: SQLitePersistentStorePolicy(
                maxFootprintBytes: 64 * mib,
                freeSpaceFloorBytes: 0,
                transactionReserveBytes: reserve,
                storageVolumePath: directory.path
            )
        )
        for index in 0..<200 {
            try await store.insert(alert: makeAlert(index))
        }
        try addFreelistPadding(
            databasePath: databasePath,
            bytes: 4 * Int(mib)
        )

        let before = try measureDatabaseFootprintBytes(dbPath: databasePath)
        // Make the current footprint exactly target+1 while it remains below
        // the ordinary hard boundary. Periodic maintenance would correctly
        // no-op here; startup must create the second reserve of headroom.
        let boundary = AlertsSizeCapBoundary(
            nominalCapBytes: before + 2 * reserve - 1,
            transactionReserveBytes: reserve
        )
        #expect(before == boundary.recoveryTargetBytes + 1)
        #expect(before <= boundary.hardAdmissionBoundaryBytes)
        #expect(!boundary.requiresMaintenance(footprintBytes: before))
        #expect(boundary.requiresStartupConvergence(
            footprintBytes: before
        ))

        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: boundary.nominalCapBytes,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: reserve,
            storageVolumePath: directory.path
        )
        let adopted = try #require(await store.updateStorageAdmission(policy))
        #expect(adopted.latchedFailure == nil,
                "target+1 is still inside ordinary admission")
        let rowsBefore = try await store.count()

        let result = await recoverAlertStoreBeforeProducers(
            alertStore: store,
            dbPath: databasePath,
            alertCapBytes: 64 * mib,
            evidenceCapBytes: 64 * mib,
            boundary: boundary
        )
        #expect(result.writableBeforeProducers)
        #expect(try #require(result.lastFootprintBytes)
            <= boundary.recoveryTargetBytes)
        #expect(try await store.count() < rowsBefore)
    }

    @Test("family in cap-reserve dead zone is reclaimed and no-write reprobe recovers")
    func deadZoneRecoveryRestoresWrites() async throws {
        let directory = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let databasePath = directory.appendingPathComponent("alerts.db").path
        let bootstrapPolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 64 * mib,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: 8 * mib,
            storageVolumePath: directory.path
        )
        let store = try AlertStore(
            directory: directory.path,
            storagePolicy: bootstrapPolicy
        )
        for index in 0..<200 {
            try await store.insert(alert: makeAlert(index))
        }
        try addFreelistPadding(
            databasePath: databasePath,
            bytes: 4 * Int(mib)
        )

        let before = try measureDatabaseFootprintBytes(dbPath: databasePath)
        let reserve = 8 * mib
        let boundary = AlertsSizeCapBoundary(
            nominalCapBytes: before + reserve / 2,
            transactionReserveBytes: reserve
        )
        #expect(before < boundary.nominalCapBytes)
        #expect(before > boundary.hardAdmissionBoundaryBytes)
        #expect(try await store.alertsAllocatedBytes() < 64 * mib)
        #expect(try await store.refreshEvidenceBudgetSnapshot(
            maxBytes: 64 * mib
        ).allocatedBytes < 64 * mib)

        let blocked = try #require(await store.updateStorageAdmission(
            SQLitePersistentStorePolicy(
                maxFootprintBytes: boundary.nominalCapBytes,
                freeSpaceFloorBytes: 0,
                transactionReserveBytes: reserve,
                storageVolumePath: directory.path
            )
        ))
        #expect(blocked.latchedFailure != nil)

        let countBefore = try await store.count()
        #expect(await enforceAlertsSizeCap(
            alertStore: store,
            dbPath: databasePath,
            alertCapBytes: 64 * mib,
            evidenceCapBytes: 64 * mib,
            boundary: boundary
        ))
        let after = try measureDatabaseFootprintBytes(dbPath: databasePath)
        #expect(after <= boundary.hardAdmissionBoundaryBytes)
        let countAfterMaintenance = try await store.count()
        #expect(countAfterMaintenance < countBefore)

        // Maintenance admission deliberately preserves the pressure latch.
        // Recovery must be proven through the ordinary gate and writer reopen,
        // without risking an irreversible first-epoch alert as a test write.
        let recovered = try await store.reprobeStorageAdmissionForWrite()
        #expect(recovered.latchedFailure == nil)
        #expect(!recovered.pageLimitPending)
        #expect(try await store.count() == countAfterMaintenance)
    }
}

@Suite("Alerts family headroom")
struct AlertsFamilyHeadroomTests {
    private let mib: Int64 = 1_048_576

    @Test("The family blocks writes while both component budgets look satisfied")
    func componentBudgetsCanBothPassWhileTheFamilyBlocks() {
        // Reproduces the installed-host state that paused alert-evidence
        // writes. The family cap is exactly alertsMaxSizeMB + evidenceMaxSizeMB
        // (100 + 100), and the footprint additionally carries indexes, the WAL,
        // free pages and the transaction reserve -- none of which count against
        // either component budget. Measured on the reference host:
        //   alert_evidence 99.9 MB (at its cap)   -> its enforcement no-ops
        //   alerts         78.3 MB (under its cap) -> its enforcement no-ops
        //   family        201,328,184 bytes > 201,326,592 admission boundary
        // so only the FAMILY pass can clear it, and writes stay paused until it
        // runs. That is what the early-fire watchdog now reacts to.
        let boundary = AlertsSizeCapBoundary(
            nominalCapBytes: 200 * mib,
            transactionReserveBytes: 8 * mib
        )
        #expect(boundary.hardAdmissionBoundaryBytes == 201_326_592)
        #expect(boundary.requiresMaintenance(footprintBytes: 201_328_184))

        // One byte under the boundary must NOT drag the watchdog into work.
        #expect(
            !boundary.requiresMaintenance(
                footprintBytes: boundary.hardAdmissionBoundaryBytes - 1
            )
        )
    }

    @Test("A family within its admission boundary needs no maintenance")
    func settledFamilyIsQuiet() {
        let boundary = AlertsSizeCapBoundary(
            nominalCapBytes: 200 * mib,
            transactionReserveBytes: 8 * mib
        )
        // 185.6 MB -- the footprint the reference host recovered to, which
        // cleared the pause.
        #expect(!boundary.requiresMaintenance(footprintBytes: 194_641_920))
    }
}

@Suite("Alerts family component trim")
struct AlertsFamilyComponentTrimTests {
    private let mib: Int64 = 1_048_576

    @Test("Both components at target fit inside the family write boundary")
    func componentsAtTargetFitTheFamily() {
        // The defect: caps of 100 + 100 exactly equal the 200 MiB family cap,
        // so both components at their caps put the family past the boundary
        // that gates writes, while each component enforcer correctly no-ops.
        let componentCap = 100 * mib
        let trim = alertsFamilyComponentTrimBytes(componentCapBytes: componentCap)
        let target = componentCap - trim
        let boundary = AlertsSizeCapBoundary(
            nominalCapBytes: 200 * mib,
            transactionReserveBytes: 8 * mib
        )
        // Two components at target, plus the measured shared overhead that
        // belongs to neither (indexes ~4.6 MB + WAL ~4.3 MB on the reference
        // host), must land under the admission boundary.
        let sharedOverhead: Int64 = 9 * mib
        #expect(target * 2 + sharedOverhead <= boundary.hardAdmissionBoundaryBytes)
        // And with real margin, not by a hair: the freelist is not in the 9 MiB.
        #expect(
            boundary.hardAdmissionBoundaryBytes - (target * 2 + sharedOverhead)
                >= 4 * mib
        )
        #expect(!boundary.requiresMaintenance(footprintBytes: target * 2 + sharedOverhead))
    }

    @Test("A small configured cap is not trimmed to nothing")
    func smallCapsKeepMostOfTheirBudget() {
        // Proportional with a ceiling, so an 8 MiB cap loses 1 MiB, not 8.
        #expect(alertsFamilyComponentTrimBytes(componentCapBytes: 8 * mib) == mib)
        #expect(alertsFamilyComponentTrimBytes(componentCapBytes: 0) == 0)
        // ...and a large cap is bounded by the ceiling rather than scaling away.
        #expect(alertsFamilyComponentTrimBytes(componentCapBytes: 1024 * mib) == 12 * mib)
    }
}
