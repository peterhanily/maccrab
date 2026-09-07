// EventsSizeCapIntervalTests.swift
//
// v1.12.6: regression coverage for the configurable events.db size-cap
// sweep cadence and the ladder-collapse fix in `runAdaptiveRollupSweep`.
//
// Three guarantees under test:
//   1. `eventsSizeCapIntervalMinutes` round-trips through
//      `daemon_config.json` AND survives a partial decode (only the
//      cadence key set; every other field falls back to default —
//      the v1.6.14 partial-decode guarantee).
//   2. The adaptive cutoff ladder never invents a cutoff below the
//      15-minute raw-event forensic/correlation floor. At the floor,
//      one honest rung is correct; [15, 14, 13] was not progressive
//      retention, it was silent violation of the promised window.
//   3. `runAdaptiveRollupSweep` integrates end-to-end: insert events
//      past the configured cap, trigger the sweep, observe both
//      Layer-2 (`rollUpAndPrune`) and Layer-3 (`pruneOldest`)
//      bringing the DB under cap.

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Events size-cap cadence + adaptive ladder (v1.12.6)")
struct EventsSizeCapIntervalTests {

    // MARK: - Helpers

    private func makeTempStore() async throws -> (EventStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-sizecap-interval-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp)
    }

    /// Insert `count` events spread across an hour ending `secondsAgo` ago.
    /// We backdate the timestamps so Layer-2's hot-tier cutoff (15 min)
    /// captures them — otherwise the sweep finds nothing to roll up and
    /// falls through to Layer 3 immediately, hiding the Layer-2 contract.
    private func insertSampleSpread(
        _ store: EventStore,
        count: Int,
        endingSecondsAgo: TimeInterval = 1800
    ) async throws {
        let now = Date()
        for i in 0..<count {
            // Spread evenly across the last hour, all timestamps older
            // than `endingSecondsAgo` so the 15-min cutoff is past them.
            let age = endingSecondsAgo + Double(i) * (3600.0 / Double(count))
            let ts = now.addingTimeInterval(-age)
            let proc = ProcessInfo(
                pid: Int32(2000 + i), ppid: 1, rpid: 1,
                name: "sweepfx\(i)", executable: "/bin/sweepfx\(i)",
                commandLine: "/bin/sweepfx\(i)", args: [],
                workingDirectory: "/",
                userId: 501, userName: "t", groupId: 20,
                startTime: ts,
                ancestors: [],
                isPlatformBinary: false
            )
            let ev = Event(
                timestamp: ts,
                eventCategory: .process, eventType: .start,
                eventAction: "exec", process: proc
            )
            try await store.insert(event: ev)
        }
    }

    /// Insert one event of a given category at a given timestamp. Used by the
    /// per-category-floor integration tests (v1.21.4) that mix a file flood
    /// with a small fixed set of exec rows.
    private func insertCat(
        _ store: EventStore, category: EventCategory, at ts: Date, tag: String
    ) async throws {
        let proc = ProcessInfo(
            pid: 1, ppid: 1, rpid: 1,
            name: tag, executable: "/bin/\(tag)",
            commandLine: "/bin/\(tag)", args: [],
            workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: ts, ancestors: [], isPlatformBinary: false
        )
        let type: EventType = category == .process ? .start : .creation
        try await store.insert(event: Event(
            timestamp: ts, eventCategory: category, eventType: type,
            eventAction: "x", process: proc
        ))
    }

    // MARK: - 1. DaemonConfig round-trip for the new field

    @Test("eventsSizeCapIntervalMinutes has a sensible default")
    func intervalDefault() {
        let cfg = DaemonConfig()
        #expect(cfg.storage.eventsSizeCapIntervalMinutes == 60,
                "Default cadence should be 60 min (replaces v1.10.0 hardcoded 6h)")
    }

    @Test("eventsSizeCapIntervalMinutes round-trips through camelCase daemon_config.json")
    func intervalRoundTripsCamelCase() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "storage": {
            "eventsSizeCapIntervalMinutes": 5
          }
        }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsSizeCapIntervalMinutes == 5)
    }

    @Test("eventsSizeCapIntervalMinutes round-trips through snake_case daemon_config.json")
    func intervalRoundTripsSnakeCase() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "storage": {
            "events_size_cap_interval_minutes": 15
          }
        }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsSizeCapIntervalMinutes == 15)
    }

    /// v1.6.14 partial-decode guarantee: setting only one storage key
    /// must NOT reset every other field to the in-code default. This
    /// was the bug class that left every operator who copied the
    /// CLAUDE.md example silently running pure defaults.
    @Test("partial config with only eventsSizeCapIntervalMinutes leaves other fields at defaults")
    func partialConfigPreservesDefaults() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "storage": {
            "eventsSizeCapIntervalMinutes": 10
          }
        }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsSizeCapIntervalMinutes == 10)
        // Sibling storage fields untouched
        #expect(cfg.storage.eventsMaxSizeMB == 476)
        #expect(cfg.storage.eventsHotTierMinutes == 30)
        #expect(cfg.storage.alertsRetentionDays == 365)
        // Unrelated top-level field untouched
        #expect(cfg.behaviorAlertThreshold == 10.0)
    }

    @Test("DaemonConfig encode→decode preserves eventsSizeCapIntervalMinutes")
    func encodeDecodeRoundTrip() throws {
        var cfg = DaemonConfig()
        cfg.storage.eventsSizeCapIntervalMinutes = 42
        let encoded = try JSONEncoder().encode(cfg)
        let decoded = try #require(DaemonConfig.decode(encoded))
        #expect(decoded.storage.eventsSizeCapIntervalMinutes == 42)
    }

    // MARK: - 1b. processEventsFloorMinutes (v1.21.4) config plumbing

    @Test("processEventsFloorMinutes has a sensible default (60)")
    func floorDefault() {
        #expect(DaemonConfig().storage.processEventsFloorMinutes == 60)
    }

    @Test("processEventsFloorMinutes round-trips through camelCase + snake_case daemon_config.json")
    func floorRoundTrips() throws {
        for (key, value) in [("processEventsFloorMinutes", 90), ("process_events_floor_minutes", 120)] {
            let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
            try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(atPath: tmp) }

            let json = "{ \"storage\": { \"\(key)\": \(value) } }"
            try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

            let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
            #expect(cfg.storage.processEventsFloorMinutes == value,
                    "\(key) should decode to \(value)")
            // Sibling storage fields untouched by the partial decode.
            #expect(cfg.storage.eventsMaxSizeMB == 476)
            #expect(cfg.storage.eventsHotTierMinutes == 30)
        }
    }

    // MARK: - 1c. Exact reserve-aware maintenance boundary

    @Test("300 MiB events cap derives exact admission and proactive boundaries")
    func exactReserveBoundaryArithmetic() {
        let boundary = EventsSizeCapBoundary(maxSizeMiB: 300)

        #expect(boundary.nominalCapBytes == 314_572_800)
        #expect(boundary.hardAdmissionBoundaryBytes == 247_463_936)
        #expect(boundary.fileLaneAdmissionBoundaryBytes == 216_006_656)
        #expect(boundary.proactiveSweepBoundaryBytes == 216_006_656)
        // Two 32-MiB producer/settlement reserves plus the 30-MiB priority
        // reserve leave 206 MiB, below the historical 240-MiB target.
        #expect(boundary.targetBytes == 216_006_656)
    }

    @Test("convergence leaves both producer reserves and the file lane's priority headroom",
          arguments: [112, 128, 300, 320, 376, 640, 700, Int.max])
    func convergedFootprintSupportsMaximumProducer(capMiB: Int) {
        let boundary = EventsSizeCapBoundary(maxSizeMiB: capMiB)
        let reserve = SQLitePersistentStorePolicy.eventTransactionReserveBytes
        let priority = EventStore.priorityLaneReserveBytes(
            maxFootprintBytes: boundary.nominalCapBytes
        )
        // The production journal validates the base estimate <= reserve, then
        // charges a separate complete postcommit reserve for settlement.
        for baseEstimate in [Int64(1), reserve / 2, reserve] {
            #expect(boundary.targetBytes + baseEstimate + reserve + priority
                <= boundary.nominalCapBytes)
            #expect(boundary.proactiveSweepBoundaryBytes + baseEstimate + reserve + priority
                <= boundary.nominalCapBytes)
        }
        #expect(boundary.targetBytes >= reserve)
        #expect(boundary.fileLaneAdmissionBoundaryBytes + 1 + reserve + reserve + priority
            > boundary.nominalCapBytes)
        #expect(boundary.hardAdmissionBoundaryBytes + reserve + reserve
            == boundary.nominalCapBytes)
    }

    @Test("factory budget preserves the prior retention allowance with the missing reserve included")
    func factoryBudgetPreservesPriorAllowance() {
        let capMiB = DaemonConfig.StorageConfig().effectiveEventsFamilyMaxSizeMB
        let boundary = EventsSizeCapBoundary(maxSizeMiB: capMiB)
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        // Prior 340-MiB policy: proactive = 340 - 32 - 34 = 274 MiB,
        // target = 80% * 340 = 272 MiB. Preserve both existing allowances.
        #expect(boundary.proactiveSweepBoundaryBytes >= 274 * mib)
        #expect(boundary.targetBytes >= 272 * mib)
        #expect(EventsSizeCapBoundary(maxSizeMiB: capMiB - 1)
            .proactiveSweepBoundaryBytes < 274 * mib)
    }

    @Test("manual and watchdog decision covers the hard-boundary-to-cap gap")
    func exactBoundaryDecisionCoversAdmissionGap() {
        let boundary = EventsSizeCapBoundary(maxSizeMiB: 300)

        #expect(!boundary.requiresMaintenance(
            footprintBytes: boundary.proactiveSweepBoundaryBytes
        ))
        #expect(boundary.requiresMaintenance(
            footprintBytes: boundary.proactiveSweepBoundaryBytes + 1
        ))
        #expect(boundary.requiresMaintenance(
            footprintBytes: boundary.hardAdmissionBoundaryBytes
        ))
        #expect(boundary.requiresMaintenance(
            footprintBytes: boundary.nominalCapBytes - 1
        ))

        // The old decimal-MB guard treated this as exactly "300 MB" and did
        // not run (`300 > configured 300` is false), even though exact binary-
        // MiB admission had already paused writes below it.
        let strandedFootprint: Int64 = 300_999_999
        #expect(strandedFootprint / 1_000_000 == 300)
        #expect(strandedFootprint > boundary.hardAdmissionBoundaryBytes)
        #expect(strandedFootprint < boundary.nominalCapBytes)
        #expect(boundary.requiresMaintenance(footprintBytes: strandedFootprint))
    }

    @Test("startup converges the writable interval above the retention target")
    func startupConvergesTargetToProactiveInterval() {
        let boundary = EventsSizeCapBoundary(maxSizeMiB: 700)
        let stranded = boundary.targetBytes + 1

        #expect(stranded <= boundary.proactiveSweepBoundaryBytes)
        #expect(!boundary.requiresMaintenance(footprintBytes: stranded))
        #expect(boundary.requiresStartupConvergence(
            footprintBytes: stranded
        ))
        #expect(!boundary.requiresStartupConvergence(
            footprintBytes: boundary.targetBytes
        ))
    }

    @Test("shipped event budgets clear the measured 15-minute structural floor")
    func defaultBudgetClearsMeasuredForensicFloor() {
        // rc.11 installed-host post-sweep floor, expressed in the same exact
        // bytes used by admission (302.7 decimal MB). The upgraded store still
        // owned 32,329,728 physical bytes of frozen legacy alert evidence; a
        // fresh schema-v8 store does not. The installed heartbeat separately
        // charged 34,492,416 bytes after allocator/index accounting, which is
        // what production rounds up for the temporary transition reserve.
        let installedFloorBytes: Int64 = 302_700_000
        let legacyOwnedBytes: Int64 = 32_329_728
        let legacyChargedBytes: Int64 = 34_492_416
        let freshFloorBytes = installedFloorBytes - legacyOwnedBytes
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let measuredTransitionReserveMiB = Int(
            (legacyChargedBytes - 1) / mib + 1
        )

        func fileLaneBoundary(capMiB: Int) -> Int64 {
            let cap = Int64(capMiB) * 1_048_576
            return cap
                - 2 * SQLitePersistentStorePolicy.eventTransactionReserveBytes
                - EventStore.priorityLaneReserveBytes(
                    maxFootprintBytes: cap
                )
        }

        // Production uses charged bytes, not physical DBSTAT ownership. The
        // factory budget preserves its prior retention allowance after adding
        // the producer's separate base-transaction headroom.
        #expect(measuredTransitionReserveMiB == 33)
        let factoryCapMiB = DaemonConfig.StorageConfig().effectiveEventsFamilyMaxSizeMB
        #expect(factoryCapMiB == 376)
        let upgradedCapMiB = factoryCapMiB + measuredTransitionReserveMiB
        #expect(upgradedCapMiB == 409)
        let upgraded = EventsSizeCapBoundary(maxSizeMiB: upgradedCapMiB)
        #expect(upgraded.targetBytes > installedFloorBytes)
        #expect(fileLaneBoundary(capMiB: upgradedCapMiB)
            > installedFloorBytes)

        let fresh = EventsSizeCapBoundary(maxSizeMiB: factoryCapMiB)
        #expect(fresh.targetBytes > freshFloorBytes)
        #expect(fileLaneBoundary(capMiB: factoryCapMiB) > freshFloorBytes)
        #expect(EventRetentionFloor.minutes == 15)
    }

    @Test("undersized and extreme event caps retain a positive safe maintenance window")
    func boundaryRejectsZeroTargetConfigurations() {
        let minimumMiB = DaemonConfig.StorageConfig.minimumEventsSizeMiB
        #expect(minimumMiB == 112)

        // These were all accepted as 50–65 MiB before the adversarial pass;
        // subtracting two fixed 32-MiB reserves yielded a 0–1 MiB target.
        for requested in [50, 64, 65, minimumMiB] {
            let boundary = EventsSizeCapBoundary(maxSizeMiB: requested)
            #expect(boundary.nominalCapBytes == 112 * 1_048_576)
            #expect(boundary.hardAdmissionBoundaryBytes == 48 * 1_048_576)
            #expect(boundary.proactiveSweepBoundaryBytes == 32 * 1_048_576)
            #expect(boundary.targetBytes == 32 * 1_048_576)
            #expect(boundary.targetBytes > 0)
            #expect(boundary.targetBytes < boundary.hardAdmissionBoundaryBytes)
        }

        var config = DaemonConfig.StorageConfig()
        config.eventsMaxSizeMB = 50
        let clamped = config.clampedToSafeFloors()
        // eventsMaxSizeMB is the historical event+evidence envelope. Its safe
        // floor must preserve both the 112 MiB event-family operating window and
        // the independently budgeted 50 MiB evidence tier.
        #expect(clamped.eventsMaxSizeMB == minimumMiB + 50)
        #expect(clamped.effectiveEventsFamilyMaxSizeMB == minimumMiB)

        // Explicit prior settings remain authoritative; this is not the new
        // factory default and is not inferred to be one during config loading.
        let customBoundary = EventsSizeCapBoundary(maxSizeMiB: 340)
        #expect(customBoundary.nominalCapBytes == 340 * 1_048_576)
        #expect(customBoundary.proactiveSweepBoundaryBytes > 0)
        #expect(customBoundary.targetBytes > 0)

        let extreme = EventsSizeCapBoundary(maxSizeMiB: .max)
        #expect(extreme.nominalCapBytes
            == Int64(DaemonConfig.StorageConfig.maximumSizeMiB) * 1_048_576)
        #expect(extreme.targetBytes > 0)
        #expect(extreme.targetBytes < extreme.hardAdmissionBoundaryBytes)
    }

    @Test("maintenance footprint uses the authoritative four-file family probe")
    func exactFootprintIncludesJournalAndRejectsPartialFamily() throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-footprint-parity-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        let path = tmp.appendingPathComponent("events.db").path

        try Data(repeating: 1, count: 11).write(to: URL(fileURLWithPath: path))
        try Data(repeating: 2, count: 13).write(to: URL(fileURLWithPath: path + "-wal"))
        try Data(repeating: 3, count: 17).write(to: URL(fileURLWithPath: path + "-shm"))
        try Data(repeating: 4, count: 19).write(to: URL(fileURLWithPath: path + "-journal"))

        #expect(try measureDatabaseFootprintBytes(dbPath: path) == 60)
        #expect(try measureDatabaseFootprintBytes(dbPath: path)
            == SQLitePersistentStoreAdmission.measureFamily(path))

        try FileManager.default.removeItem(atPath: path)
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try measureDatabaseFootprintBytes(dbPath: path)
        }
    }

    // MARK: - 2. Adaptive ladder hard-floor contract

    @Test("adaptive ladder stops exactly at the 15-minute hard floor")
    func ladderStopsAtFloor() {
        #expect(EventRetentionFloor.adaptiveCutoffs(hotTierMinutes: 15) == [15])
        #expect(EventRetentionFloor.adaptiveCutoffs(hotTierMinutes: 1) == [15])
    }

    @Test("adaptive ladder deduplicates the floor at hotTierMinutes=30")
    func ladderAt30Min() {
        #expect(EventRetentionFloor.adaptiveCutoffs(hotTierMinutes: 30) == [30, 15])
    }

    @Test("adaptive ladder retains three distinct cutoffs at hotTierMinutes=120")
    func ladderAt120Min() {
        #expect(EventRetentionFloor.adaptiveCutoffs(hotTierMinutes: 120) == [120, 60, 30])
    }

    @Test("an unmet retention budget stays degraded until a real convergence result")
    func retentionBudgetHealthIsStickyAndHonest() {
        let boundary = EventsSizeCapBoundary(maxSizeMiB: 300)
        let health = EventRetentionBudgetHealth()

        #expect(health.snapshot().state == "unknown")
        health.recordSweep(
            observedFootprintBytes: boundary.targetBytes + 1,
            boundary: boundary,
            at: Date(timeIntervalSince1970: 100)
        )
        let degraded = health.snapshot()
        #expect(degraded.state == "degraded_budget_unmet")
        #expect(degraded.sticky)
        #expect(degraded.observedFootprintBytes == boundary.targetBytes + 1)
        #expect(degraded.evaluatedAtUnix == 100)

        // Merely reading/sampling the state cannot turn an infeasible budget
        // green. A material configuration change returns it to honest-unknown.
        #expect(health.snapshot() == degraded)
        health.recordConfigurationChange()
        #expect(health.snapshot().state == "unknown")
        #expect(health.snapshot().reason == "configuration_changed_awaiting_sweep")

        health.recordSweep(
            observedFootprintBytes: boundary.targetBytes,
            boundary: boundary
        )
        #expect(health.snapshot().state == "converged")
        #expect(!health.snapshot().sticky)
    }

    @Test("watchdog backoff resets only on convergence or material config change")
    func watchdogBackoffDoesNotResetOnOrdinarySampling() {
        let backoff = SizeCapWatchdogBackoff()
        backoff.observeConfiguration("420:64:30:60")
        #expect(backoff.mayFire())

        _ = backoff.recordSweep(stillOver: true)
        #expect(!backoff.mayFire())
        backoff.observeConfiguration("420:64:30:60")
        #expect(!backoff.mayFire(),
                "re-observing unchanged config must not clear an ineffective-sweep backoff")

        backoff.observeConfiguration("512:64:30:60")
        #expect(backoff.mayFire(), "a material budget change invalidates the old conclusion")
        _ = backoff.recordSweep(stillOver: true)
        #expect(!backoff.mayFire())
        _ = backoff.recordSweep(stillOver: false)
        #expect(backoff.mayFire(), "only an actual converged sweep re-arms immediately")
    }

    @Test("retention telemetry names a forensic floor, never a SequenceEngine rebuild")
    func retentionFloorTruthDoesNotDrift() throws {
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
        #expect(timers.contains("events_retention_below_forensic_floor"))
        #expect(timers.contains(
            "events_retained_lookback_seconds_by_category"
        ))
        #expect(timers.contains("SequenceEngine does not currently rehydrate from events.db"))
        #expect(!timers.contains("events_retention_below_sequence_floor"))
        #expect(!timers.localizedCaseInsensitiveContains("sequence-rebuild floor"))
    }

    @Test("retention health uses oldest lookback, not inter-observation span")
    func retentionHealthUsesOldestLookback() async throws {
        let (store, directory) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        let asOf = Date(timeIntervalSince1970: 100_000)
        try await insertCat(
            store,
            category: .tcc,
            at: asOf.addingTimeInterval(-900),
            tag: "tcc-oldest"
        )
        try await insertCat(
            store,
            category: .tcc,
            at: asOf.addingTimeInterval(-5),
            tag: "tcc-newest"
        )

        let window = try #require(
            await store.retainedWindowSecondsByCategory(asOf: asOf)[
                EventCategory.tcc.rawValue
            ]
        )
        #expect(window.spanSeconds == 895)
        #expect(window.lookbackSeconds == 900)
    }

    @Test("setup proves event and alert storage before every producer activation")
    func startupRecoveryEstablishesWritableFirstEpoch() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let setup = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonSetup.swift"
            ),
            encoding: .utf8
        )
        let timers = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonTimers.swift"
            ),
            encoding: .utf8
        )
        let eventRecovery = try #require(setup.range(of:
            "let eventStartupRecovery = await recoverEventStoreBeforeProducers("
        ))
        let eventGuard = try #require(setup.range(of:
            "guard eventStartupRecovery.writableBeforeProducers else"
        ))
        let alertRecovery = try #require(setup.range(of:
            "let alertStartupRecovery = await recoverAlertStoreBeforeProducers("
        ))
        let alertGuard = try #require(setup.range(of:
            "guard alertStartupRecovery.writableBeforeProducers else"
        ))
        let finalMarker = try #require(setup.range(of:
            "// FINAL_PRE_INGESTION_STORAGE_ACTIVATION_BOUNDARY"
        ))
        let eventActivationProbe = try #require(setup.range(of:
            "reprobeEventStoreAtActivationBoundary("
        ))
        let alertActivationProbe = try #require(setup.range(of:
            "reprobeAlertStoreAtActivationBoundary("
        ))
        let graphActivationProof = try #require(setup.range(of:
            "causalStoreStartupRecovery = activationProof"
        ))
        #expect(eventRecovery.lowerBound < alertRecovery.lowerBound)
        #expect(eventRecovery.lowerBound < eventGuard.lowerBound)
        #expect(alertRecovery.lowerBound < alertGuard.lowerBound)
        #expect(finalMarker.lowerBound < eventActivationProbe.lowerBound)
        #expect(eventActivationProbe.lowerBound < alertActivationProbe.lowerBound)
        #expect(alertActivationProbe.lowerBound < graphActivationProof.lowerBound)

        // These are the complete Setup-time producer census from the rc.11
        // audit. Constructor-active sources are listed alongside explicit
        // starts and the first AlertSink flush so future reordering cannot let
        // a collector-local buffer/drop counter move during storage recovery.
        for producer in [
            "await mcpMonitor.start()",
            "if await fleet.start()",
            "await dnsCollector.start()",
            "await eventTapMonitor.start()",
            "await systemPolicyMonitor.start()",
            "await fsEventsCollector.start()",
            "ulCollector = try UnifiedLogCollector()",
            "collector = try ESCollector(",
            "await esloggerCollector!.start()",
            "await kdebug.start()",
            "for alert in bootstrapAlerts",
            "try await receiver.start()",
            "label: \"deception-deploy\"",
            "label: \"threat-intel-hydration\"",
        ] {
            let activation = try #require(setup.range(of: producer))
            #expect(
                alertGuard.lowerBound < activation.lowerBound,
                "event/alert storage proof must precede \(producer)"
            )
            #expect(graphActivationProof.lowerBound < activation.lowerBound,
                    "fresh storage proofs must precede \(producer)")
        }

        let helperStart = try #require(timers.range(of:
            "func recoverEventStoreBeforeProducers("
        ))
        let helperTail = try #require(timers.range(
            of: "// MARK: - Size-cap enforcement",
            range: helperStart.upperBound..<timers.endIndex
        ))
        let helper = timers[helperStart.lowerBound..<helperTail.lowerBound]
        #expect(helper.contains("retentionBudgetHealth.recordSweep("))
        #expect(helper.contains("reprobeStorageAdmissionForWrite(lane: .priority)"))
        #expect(helper.contains("reprobeStorageAdmissionForWrite(lane: .file)"))
        #expect(timers.contains("func reprobeEventStoreAtActivationBoundary("))
        #expect(timers.contains("func reprobeAlertStoreAtActivationBoundary("))
        let pinPreflight = try #require(helper.range(of:
            "eventStore.walCheckpointTruncate()"
        ))
        let destructiveEnforcer = try #require(helper.range(of:
            "enforceDatabaseSizeCap("
        ))
        #expect(pinPreflight.lowerBound < destructiveEnforcer.lowerBound,
                "startup must detect a reader pin before pruning event rows")
        let pinPostflight = try #require(helper.range(
            of: "eventStore.walCheckpointTruncate()",
            range: destructiveEnforcer.upperBound..<helper.endIndex
        ))
        #expect(destructiveEnforcer.lowerBound < pinPostflight.lowerBound,
                "startup must detect a reader that arrives during maintenance")
    }

    // MARK: - 3. Integration: runAdaptiveRollupSweep drives prune end-to-end

    /// Backdated source timestamps cannot bypass rc.13's durable-admission
    /// floor. The legacy adaptive sweep may target those timestamps, but fresh
    /// canonical blocks remain intact until whole-block expiry is eligible.
    @Test("runAdaptiveRollupSweep cannot prune fresh journal blocks with backdated source time")
    func sweepDrivesPrune() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Insert a non-trivial block corpus whose source timestamps are older
        // than the adaptive cutoff. Only their admission age may make them
        // eligible for canonical expiry.
        try await insertSampleSpread(store, count: 5_000, endingSecondsAgo: 3600)
        let before = try await store.count()
        #expect(before == 5_000)

        // VACUUM to write everything to disk so the footprint measurement
        // matches reality.
        try await store.vacuum()
        let dbPath = tmp.appendingPathComponent("events.db").path

        // Tight cap to force Layer 2 + Layer 3 to do work. The
        // sweep targets 80% of cap; a 1 MB cap guarantees the legacy adaptive
        // logic engages even though it must leave fresh journal blocks alone.
        await runAdaptiveRollupSweep(
            eventStore: store,
            dbPath: dbPath,
            targetSizeBytes: 1_000_000,
            capSizeBytes: 1_000_000,
            hotTierMinutes: 30,
            aggregateDays: 90,
            alertsRetentionDays: 365
        )

        // The source timestamps are old, but every block was admitted now and
        // owns the complete 15-minute floor. Generic rollup/oldest-row pruning
        // is legacy-only and cannot manufacture convergence by deleting it.
        let after = try await store.count()
        #expect(after == before,
                "adaptive legacy pruning must not delete fresh journal evidence (was \(before), now \(after))")
        #expect(try await store.maintenanceRetainedRecordCount() == before)
    }

    /// Layer 3 may request oldest-first pruning when the tightest Layer-2
    /// cutoff still leaves the DB over cap, but it must stop at the hard floor.
    @Test("runAdaptiveRollupSweep refuses to delete rows inside the 15-minute floor")
    func sweepStopsAtHardFloor() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Use *recent* events so Layer 2 cannot touch them. Layer 3 may
        // attempt a row target, but the hard floor must return short rather
        // than delete recent evidence merely to make the byte cap look met.
        let now = Date()
        for i in 0..<2_000 {
            let proc = ProcessInfo(
                pid: Int32(3000 + i), ppid: 1, rpid: 1,
                name: "recent\(i)", executable: "/bin/recent\(i)",
                commandLine: "/bin/recent\(i)", args: [],
                workingDirectory: "/",
                userId: 501, userName: "t", groupId: 20,
                startTime: now,
                ancestors: [],
                isPlatformBinary: false
            )
            // Spread within the last 5 minutes — well inside even the
            // tightest ladder rung — so Layer 2 leaves them alone.
            let ts = now.addingTimeInterval(-Double(i % 300))
            try await store.insert(event: Event(
                timestamp: ts,
                eventCategory: .process, eventType: .start,
                eventAction: "exec", process: proc
            ))
        }
        try await store.vacuum()
        let dbPath = tmp.appendingPathComponent("events.db").path

        let before = try await store.count()
        #expect(before == 2_000)

        await runAdaptiveRollupSweep(
            eventStore: store,
            dbPath: dbPath,
            targetSizeBytes: 1_000_000,
            capSizeBytes: 1_000_000,
            hotTierMinutes: 15,
            aggregateDays: 90,
            alertsRetentionDays: 365
        )

        let after = try await store.count()
        #expect(after == before,
                "an infeasible cap must shed future persistence honestly, not erase the protected raw-event window")
    }

    // MARK: - 4. Per-category retention floor (v1.21.4)

    /// A cheap file-write flood must not make the hard all-category floor soft.
    /// With every row recent, an infeasible byte budget stays visibly unmet.
    @Test("hard floor preserves recent file and exec rows when the cap is infeasible")
    func hardFloorPreservesRecentFileFloodAndExec() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let now = Date()
        for i in 0..<2_000 {
            try await insertCat(store, category: .file, at: now.addingTimeInterval(-Double(i % 240)), tag: "flood\(i)")
        }
        for i in 0..<100 {
            try await insertCat(store, category: .process, at: now.addingTimeInterval(-Double(i % 240)), tag: "exec\(i)")
        }
        try await store.vacuum()
        let dbPath = tmp.appendingPathComponent("events.db").path

        let before = try await store.count()
        #expect(before == 2_100)

        // Cap below the footprint. Every row is inside the hard 15-minute
        // floor, so neither the file flood nor the process channel may be
        // deleted to manufacture convergence.
        let measured = try measureDatabaseFootprintBytes(dbPath: dbPath)
        #expect(measured > 1_000_000, "2.1k events should exceed the forced 1 MB cap (was \(measured) bytes)")
        let capBytes: Int64 = 1_000_000

        await runAdaptiveRollupSweep(
            eventStore: store,
            dbPath: dbPath,
            targetSizeBytes: capBytes,
            capSizeBytes: capBytes,
            hotTierMinutes: 15,
            aggregateDays: 90,
            alertsRetentionDays: 365,
            processFloorMinutes: 60
        )

        let byCat = try await store.eventCategoryCountSnapshot(
            since: .distantPast
        )
        #expect(byCat.requestedWindowComplete == false)
        #expect(byCat.gaps.total == 0)
        #expect(byCat.counts["process"] == 100, "all exec rows within the floor survive the file-storm sweep")
        #expect(byCat.counts["file"] == 2_000, "the hard floor applies to every category")
        let after = try await store.count()
        #expect(after == before, "an infeasible budget is exposed instead of erasing recent rows")
    }

    /// The category-specific process floor remains soft, but its oldest-first
    /// valve is still bounded by the separate hard all-category floor.
    @Test("hard floor overrides the process soft-floor valve for recent rows")
    func hardFloorStopsValveWhenAllProcessRowsAreRecent() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let now = Date()
        for i in 0..<2_000 {
            try await insertCat(store, category: .process, at: now.addingTimeInterval(-Double(i % 240)), tag: "exec\(i)")
        }
        try await store.vacuum()
        let dbPath = tmp.appendingPathComponent("events.db").path
        let before = try await store.count()
        #expect(before == 2_000)

        await runAdaptiveRollupSweep(
            eventStore: store,
            dbPath: dbPath,
            targetSizeBytes: 1_000_000,
            capSizeBytes: 1_000_000,
            hotTierMinutes: 15,
            aggregateDays: 90,
            alertsRetentionDays: 365,
            processFloorMinutes: 60   // every recent process row is "protected"
        )

        let after = try await store.count()
        #expect(after == before,
                "the soft category valve cannot cross the hard all-category forensic floor")
    }
}
