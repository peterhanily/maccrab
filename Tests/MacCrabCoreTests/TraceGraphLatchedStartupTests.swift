// TraceGraphLatchedStartupTests.swift
// v1.22.6 — a TraceGraph store that cannot drain below its resume target at
// boot (every remaining row inside the one-hour evidence floor) used to fail
// pre-ingestion storage, exit, and be relaunched by sysextd into the same
// store. It now starts with its graph writes latched, and the ordinary runtime
// recovery lane clears that latch once the protected rows age out.
//
// DaemonSetup.initialize needs a real support directory, Endpoint Security and
// root-owned paths, so a full boot cannot run here. These tests drive the same
// store calls and the same decision functions DaemonSetup and DaemonBootstrap
// use; the source-order tests in CausalGraphSubstrateRetentionTests pin that a
// `.notReady` store is closed and detached after its drain.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("TraceGraph latched startup")
struct TraceGraphLatchedStartupTests {
    private let mib: Int64 = 1_048_576

    private final class FaultSwitch: @unchecked Sendable {
        private let lock = NSLock()
        private var on = false

        var isOn: Bool {
            lock.lock()
            defer { lock.unlock() }
            return on
        }

        func turnOn() {
            lock.lock()
            on = true
            lock.unlock()
        }
    }

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-latched-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: url.path), url)
    }

    private func removeFamily(_ url: URL) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(atPath: url.path + suffix)
        }
    }

    private func trace(_ id: String, updatedAt: Date, payloadBytes: Int) -> Trace {
        Trace(
            id: id,
            title: "Latched startup test",
            anchorEventId: "event-\(id)",
            rootEntityId: nil,
            severity: "high",
            confidence: 1,
            createdAt: updatedAt,
            updatedAt: updatedAt,
            daemonVersion: "test",
            rulesetVersion: "test",
            policyId: "default",
            policyVersion: "1",
            policySha256: "test",
            policySnapshotJson: String(repeating: "x", count: payloadBytes),
            traceSigningKeyMode: "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy:
                "include_as_human_annotation_do_not_apply_by_default"
        )
    }

    @Test("A store above proactive whose rows are all under one hour old reaches ingestion latched",
          arguments: ["below-admission-threshold", "above-admission-threshold"])
    func protectedFloorStartsLatched(boundary: String) async throws {
        let (store, url) = try await makeStore()
        defer { removeFamily(url) }
        let now = Date(timeIntervalSince1970: 2_000_300_000)
        let protected = now.addingTimeInterval(-30 * 60)
        let count = 400
        for index in 0..<count {
            try await store.saveTrace(
                trace("protected-\(index)", updatedAt: protected, payloadBytes: 40 * 1_024),
                members: []
            )
        }
        #expect(await store.walCheckpointTruncate())
        let footprint = try #require(await store.storageFootprintBytes())
        let reserve = 8 * mib
        // Below: proactive boundary == footprint, admission threshold above it,
        // so restart begins unlatched (the rc.11 shape). Above: the footprint is
        // already past the admission threshold and the store opens blocked.
        let overThreshold = boundary == "above-admission-threshold"
        let initial = await store.updateStorageAdmission(
            maxFootprintBytes: overThreshold
                ? footprint + reserve - 1
                : footprint + 2 * mib + reserve,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: reserve
        )
        #expect(initial.blocked == overThreshold)
        #expect((initial.footprintBytes ?? -1)
                >= (initial.proactiveRecoveryThresholdBytes ?? Int64.max))

        let recovery = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 90 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours,
            now: now,
            maximumPasses: DaemonTimers.tracegraphStartupRecoveryMaximumPasses
        )
        #expect(recovery.disposition == .nonconverged(.protectedEvidenceFloor))
        #expect(!recovery.writableBeforeProducers)
        // The unlatched store would still admit writes without a headroom
        // proof, so the raw drain result alone is not a latched start.
        #expect(DaemonSetup.traceGraphStartupAdmission(recovery)
                == (overThreshold ? .latched : .notReady))

        // DaemonSetup's post-drain step.
        let startup = await DaemonSetup.admitTraceGraphStartup(
            store: store,
            recovery: recovery
        )
        #expect(startup.admission == .latched)
        let latched = try #require(startup.proof.finalAdmission)
        #expect(latched.writableHandle)
        #expect(latched.blocked)
        #expect(!latched.acceptingMutations)
        #expect(latched.reason == .footprintLimit)
        #expect(startup.proof.disposition == recovery.disposition)

        // DaemonSetup's activation-boundary reprobe keeps the latch, and the
        // outer DaemonBootstrap guard reads the retained proof as latched.
        let activation = await DaemonSetup.admitTraceGraphStartup(
            store: store,
            recovery: startup.proof.refreshed(
                finalAdmission: await store.storageAdmissionStatus()
            )
        )
        #expect(activation.admission == .latched)
        #expect(DaemonSetup.traceGraphStartupAdmission(activation.proof) == .latched)
        #expect(activation.proof.finalAdmission?.reason == .footprintLimit)

        // Latched means graph growth is refused, and nothing protected was
        // deleted to get here.
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.saveTrace(
                trace("while-latched", updatedAt: now, payloadBytes: 1_024),
                members: []
            )
        }
        #expect(try await store.loadTrace(id: "protected-0") != nil)
        #expect(try await store.loadTrace(id: "protected-\(count - 1)") != nil)

        // Runtime: once the rows age past the floor, the same bounded pass the
        // periodic lane runs drains below the resume target and clears the latch.
        let later = now.addingTimeInterval(3 * 3_600)
        var status = await store.storageAdmissionStatus()
        var passes = 0
        while status.blocked, passes < 64 {
            _ = try await store.recoverStorageBudget(
                retentionCutoff: later.addingTimeInterval(-3_600),
                orphanCutoff: later.addingTimeInterval(-3_600)
            )
            status = await store.storageAdmissionStatus()
            passes += 1
        }
        #expect(!status.blocked, "runtime recovery must clear the startup latch")
        #expect(status.acceptingMutations)
        try await store.saveTrace(
            trace("after-recovery", updatedAt: later, payloadBytes: 1_024),
            members: []
        )
        await store.close()
    }

    @Test("A store with no writable handle is not ready, so it is detached instead of starting latched")
    func closedHandleIsNotReady() async throws {
        let (store, url) = try await makeStore()
        defer { removeFamily(url) }
        await store.close()
        let recovery = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours
        )
        #expect(recovery.disposition == .nonconverged(.writableHandleUnavailable))
        let startup = await DaemonSetup.admitTraceGraphStartup(
            store: store,
            recovery: recovery
        )
        #expect(startup.admission == .notReady)
        #expect(startup.proof.finalAdmission?.writableHandle == false)
        // A detached run carries no admission at all; DaemonBootstrap admits it
        // only through its separate `!traceGraphAttached` clause.
        #expect(DaemonSetup.traceGraphStartupAdmission(
            .unavailable(reason: .lowFreeSpace)) == .notReady)
    }

    @Test("A drain that fails on an SQLite fault is not ready, never latched as footprint_limit")
    func sqliteFaultDuringDrainIsNotLatched() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-drain-fault-\(UUID().uuidString).db")
        defer { removeFamily(url) }
        let faulting = FaultSwitch()
        let corrupt = CausalGraphInjectedSQLiteFailure(resultCode: SQLITE_CORRUPT)
        let store = try await SQLiteCausalGraphStore(
            databasePath: url.path,
            transactionFailureProbe: { operation in
                operation == .begin && faulting.isOn ? corrupt : nil
            }
        )
        let now = Date(timeIntervalSince1970: 2_000_300_000)
        // Past the 90-day retention, so the first bounded pass must delete.
        let expired = now.addingTimeInterval(-100 * 24 * 3_600)
        for index in 0..<200 {
            try await store.saveTrace(
                trace("expired-\(index)", updatedAt: expired, payloadBytes: 40 * 1_024),
                members: []
            )
        }
        #expect(await store.walCheckpointTruncate())
        let footprint = try #require(await store.storageFootprintBytes())
        let reserve = 8 * mib
        let initial = await store.updateStorageAdmission(
            maxFootprintBytes: footprint + 2 * mib + reserve,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: reserve
        )
        #expect(!initial.blocked)
        // At or above proactive, hence above resume: the latch helper would
        // trip the footprint latch on this store.
        #expect((initial.footprintBytes ?? -1)
                >= (initial.proactiveRecoveryThresholdBytes ?? Int64.max))

        faulting.turnOn()
        let recovery = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 90 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours,
            now: now,
            maximumPasses: DaemonTimers.tracegraphStartupRecoveryMaximumPasses
        )
        #expect(recovery.disposition == .nonconverged(.recoveryFailed))
        #expect(DaemonSetup.traceGraphStartupAdmission(recovery) == .notReady)

        let startup = await DaemonSetup.admitTraceGraphStartup(
            store: store,
            recovery: recovery
        )
        #expect(startup.admission == .notReady)
        #expect(startup.proof == recovery)
        let status = await store.storageAdmissionStatus()
        #expect(!status.blocked, "the startup step must not trip the footprint latch")
        #expect(status.reason != .footprintLimit)
        await store.close()
    }
}
