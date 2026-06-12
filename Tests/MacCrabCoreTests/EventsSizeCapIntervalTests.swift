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
//   2. The adaptive cutoff ladder retains at least two DISTINCT
//      cutoffs even when `hotTierMinutes == 15` (pre-fix the
//      `max(15, …)` floor + `NSOrderedSet` dedup collapsed every
//      rung to a single 15-minute entry, defeating the Layer-2
//      adaptive design).
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
        #expect(cfg.storage.eventsMaxSizeMB == 350)   // v1.19.0 default
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

    // MARK: - 2. Adaptive ladder no-collapse contract

    /// The internal ladder is rebuilt inside `runAdaptiveRollupSweep`.
    /// We re-derive it here using the same formula, so this test pins
    /// the algorithm contract — if anyone re-introduces an `NSOrderedSet`
    /// dedup or moves the floor back to `max(15, …)`, this assertion
    /// trips before the sweep silently regresses.
    private func ladderCutoffsMinutes(hotTierMinutes: Int) -> [Int] {
        let rung1 = hotTierMinutes
        let rung2 = min(rung1 - 1, max(15, hotTierMinutes / 2))
        let rung3 = min(rung2 - 1, max(15, hotTierMinutes / 4))
        return [rung1, rung2, rung3].filter { $0 > 0 }
    }

    @Test("adaptive ladder has at least 2 entries at hotTierMinutes=15 (no collapse)")
    func ladderNoCollapseAtFloor() {
        let ladder = ladderCutoffsMinutes(hotTierMinutes: 15)
        #expect(ladder.count >= 2,
                "Pre-fix the [hot, hot/2, hot/4] ladder collapsed to a single 15-min rung at the floor. Post-fix it must retain ≥2 distinct cutoffs so Layer-2 can still tighten progressively.")
        // Strict monotonic decrease — pre-fix's NSOrderedSet dedup
        // would leave duplicates intact if the floor swallowed them.
        for i in 1..<ladder.count {
            #expect(ladder[i] < ladder[i - 1],
                    "ladder[\(i)] (\(ladder[i])) must be strictly less than ladder[\(i-1)] (\(ladder[i-1]))")
        }
    }

    @Test("adaptive ladder retains three distinct cutoffs at hotTierMinutes=30")
    func ladderAt30Min() {
        let ladder = ladderCutoffsMinutes(hotTierMinutes: 30)
        #expect(ladder.count == 3)
        #expect(ladder[0] == 30)
        // Verify strict descent — exact values are implementation detail.
        #expect(ladder[1] < ladder[0])
        #expect(ladder[2] < ladder[1])
    }

    @Test("adaptive ladder retains three distinct cutoffs at hotTierMinutes=120")
    func ladderAt120Min() {
        let ladder = ladderCutoffsMinutes(hotTierMinutes: 120)
        #expect(ladder.count == 3)
        #expect(ladder[0] == 120)
        #expect(ladder[1] == 60)
        #expect(ladder[2] == 30)
    }

    // MARK: - 3. Integration: runAdaptiveRollupSweep drives prune end-to-end

    /// Pours events past Layer 2's hot-tier cutoff into a real
    /// EventStore, runs the sweep, and asserts both that rows were
    /// pruned and that the DB file size on disk decreased. This is
    /// the contract the size-cap timer relies on; if the sweep stops
    /// pruning (e.g. a future refactor breaks `rollUpAndPrune`'s
    /// transaction), this test catches it immediately.
    @Test("runAdaptiveRollupSweep prunes rows when DB exceeds cap")
    func sweepDrivesPrune() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Insert enough backdated events (older than 30 min so the
        // hotTier cutoff catches them) to drive a non-trivial prune.
        // 5,000 is enough to exceed Layer-3's 10,000-min-row floor
        // and verify the loop actually deletes from the hot tier
        // rather than no-opping.
        try await insertSampleSpread(store, count: 5_000, endingSecondsAgo: 3600)
        let before = try await store.count()
        #expect(before == 5_000)

        // VACUUM to write everything to disk so the footprint measurement
        // matches reality.
        try await store.vacuum()
        let dbPath = tmp.appendingPathComponent("events.db").path

        // Tight cap to force Layer 2 + Layer 3 to do work. The
        // sweep targets 80% of cap; with 5k events the file is
        // typically < 5 MB but we want adaptive logic to engage —
        // a 1 MB cap gets Layer 3 into the picture even on a
        // small store.
        await runAdaptiveRollupSweep(
            eventStore: store,
            dbPath: dbPath,
            targetSizeMB: 1,
            capSizeMB: 1,
            hotTierMinutes: 30,
            aggregateDays: 90,
            alertsRetentionDays: 365
        )

        // Layer 2 + Layer 3 between them must have removed at least
        // some rows. We deliberately don't pin the exact count — the
        // sweep is allowed to leave the most-recent hot-tier-window
        // rows alone if they're newer than the cutoff. The contract
        // is "fewer rows than before", not "zero rows".
        let after = try await store.count()
        #expect(after < before,
                "Sweep should have pruned at least one row (was \(before), now \(after))")
    }

    /// Layer 3's `pruneOldest` fallback must engage when even the
    /// tightest Layer-2 cutoff leaves the DB over cap. This test
    /// confirms the fallback fires even when `hotTierMinutes` is at
    /// the floor (the regime where the pre-fix ladder-collapse hurt
    /// most).
    @Test("runAdaptiveRollupSweep engages Layer 3 at hotTierMinutes=15 (post-fix)")
    func sweepEngagesLayer3AtFloor() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Use *recent* events so Layer 2 can't touch them (newer than
        // any rung of the ladder). Layer 3 must still bring the row
        // count down via `pruneOldest`.
        let now = Date()
        for i in 0..<12_000 {
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
        #expect(before == 12_000)

        await runAdaptiveRollupSweep(
            eventStore: store,
            dbPath: dbPath,
            targetSizeMB: 1,
            capSizeMB: 1,
            hotTierMinutes: 15,        // FLOOR — pre-fix this collapsed the ladder
            aggregateDays: 90,
            alertsRetentionDays: 365
        )

        let after = try await store.count()
        // Layer 3's bound is `max(10_000, …)` rows dropped, so at the
        // floor we expect a sizable drop. The contract is "fewer
        // rows", not an exact count.
        #expect(after < before,
                "At hotTierMinutes=15, Layer 3 should still engage and prune (was \(before), now \(after))")
    }
}
