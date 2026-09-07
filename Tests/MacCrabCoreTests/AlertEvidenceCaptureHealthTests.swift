import Foundation
import Testing
@testable import MacCrabCore

@Suite("Alert evidence live capture age")
struct AlertEvidenceCaptureHealthTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var instant = ContinuousClock.now
        func now() -> ContinuousClock.Instant {
            lock.lock(); defer { lock.unlock() }; return instant
        }
        func advance(_ seconds: Double) {
            lock.lock(); defer { lock.unlock() }
            instant = instant.advanced(by: .seconds(seconds))
        }
    }

    private enum PlannedFailure: Error { case capture }
    private actor Gate {
        private var calls = 0
        private var release: CheckedContinuation<Void, Never>?
        private var observers: [(Int, CheckedContinuation<Void, Never>)] = []
        let failFirst: Bool
        init(failFirst: Bool = false) { self.failFirst = failFirst }
        func capture() async throws -> AlertEvidenceCaptureResult {
            calls += 1
            let ordinal = calls
            await withCheckedContinuation { continuation in
                release = continuation
                let ready = observers.filter { calls >= $0.0 }
                observers.removeAll { calls >= $0.0 }
                ready.forEach { $0.1.resume() }
            }
            try Task.checkCancellation()
            if failFirst && ordinal == 1 { throw PlannedFailure.capture }
            return .init(insertedRows: 0, duplicateRows: 0, prunedRows: 0)
        }
        func waitForCall(_ target: Int) async {
            if calls >= target { return }
            await withCheckedContinuation { observers.append((target, $0)) }
        }
        func open() { release?.resume(); release = nil }
    }

    private func alert(_ id: String) -> Alert {
        Alert(id: id, timestamp: Date(timeIntervalSince1970: 1_700_000_000),
              ruleId: "fixture.capture-age", ruleTitle: "Capture age fixture",
              severity: .high, eventId: UUID().uuidString)
    }

    @Test("Capture handoff preserves newer work age and terminal failures", arguments: [false, true])
    func queueAndSettlement(failFirst: Bool) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let clock = Clock(), gate = Gate(failFirst: failFirst)
        let sink = AlertSink(
            alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60),
            evidenceMonotonicNow: { clock.now() },
            evidenceCaptureOverride: { _, _ in try await gate.capture() }
        )
        let initial = await sink.evidenceStats()
        #expect(initial.oldestOutstandingAgeSeconds == 0)
        #expect(initial.activeOperationAgeSeconds == 0)
        _ = try await sink.insertEngineBatch(alerts: [alert("first")])
        await gate.waitForCall(1)
        clock.advance(10)
        do {
            _ = try await sink.insertEngineBatch(alerts: [alert("second")])
        } catch {
            await gate.open()
            await sink.flushEvidenceCapture()
            throw error
        }
        clock.advance(5)
        let queued = await sink.evidenceStats()
        #expect(queued.pending == 1)
        #expect(queued.inFlight == 1)
        #expect(queued.oldestOutstandingAgeSeconds == 15)
        #expect(queued.activeOperationAgeSeconds == 15)
        #expect(queued.conserved)
        await gate.open()
        await gate.waitForCall(2)
        let next = await sink.evidenceStats()
        #expect(next.pending == 0)
        #expect(next.inFlight == 1)
        #expect(next.oldestOutstandingAgeSeconds == 5)
        #expect(next.activeOperationAgeSeconds == 0)
        #expect(next.failures == (failFirst ? 1 : 0))
        clock.advance(46)
        let delayed = await sink.evidenceStats()
        #expect(delayed.oldestOutstandingAgeSeconds == 51)
        #expect(delayed.activeOperationAgeSeconds == 46)
        await gate.open()
        await sink.flushEvidenceCapture()
        let complete = await sink.evidenceStats()
        #expect(complete.oldestOutstandingAgeSeconds == 0)
        #expect(complete.activeOperationAgeSeconds == 0)
        #expect(complete.completed == (failFirst ? 1 : 2))
        #expect(complete.failures == (failFirst ? 1 : 0))
        #expect(complete.conserved)
        let restarted = AlertSink(alertStore: store, deduplicator: AlertDeduplicator())
        let fresh = await restarted.evidenceStats()
        #expect(fresh.offered == 0)
        #expect(fresh.failures == 0)
        #expect(fresh.oldestOutstandingAgeSeconds == 0)
        #expect(fresh.activeOperationAgeSeconds == 0)
    }

    @Test("Cancelled in-flight capture settles as reported shed and preserves durable pending truth")
    func cancellationConserves() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let clock = Clock(), gate = Gate()
        let sink = AlertSink(
            alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60),
            evidenceMonotonicNow: { clock.now() },
            evidenceCaptureOverride: { _, _ in try await gate.capture() }
        )
        _ = try await sink.insertEngineBatch(alerts: [alert("cancelled")])
        await gate.waitForCall(1)
        let shutdown = await sink.shutdownEvidenceCapture(timeout: .zero)
        #expect(shutdown.deadlineExpired)
        #expect(shutdown.pending == 1)
        await gate.open()
        await sink.flushEvidenceCapture()
        let settled = await sink.evidenceStats()
        #expect(settled.offered == 1)
        #expect(settled.completed == 0)
        #expect(settled.failures == 0)
        #expect(settled.shed == 1)
        #expect(settled.shedAtShutdownDeadline == 1)
        #expect(settled.pending == 0)
        #expect(settled.inFlight == 0)
        #expect(settled.oldestOutstandingAgeSeconds == 0)
        #expect(settled.activeOperationAgeSeconds == 0)
        #expect(settled.conserved)
        #expect(try await store.pendingEvidenceContextCount() == 1)
        let repeated = await sink.shutdownEvidenceCapture(timeout: .zero)
        #expect(repeated.shedAtDeadline == 1)
        #expect(repeated.pending == 0)
        #expect(repeated.completed == 0)
        #expect(!repeated.clean)
    }

    private func status(
        pending: Int = 1, inFlight: Int = 0, completed: Int = 0,
        failures: Int = 0, shed: Int = 0,
        oldest: Any? = 0, active: Any? = 0,
        omissions: [String] = []
    ) throws -> HeartbeatSnapshot.AlertEvidenceBudget {
        var raw: [String: Any] = [
            "capture_offered_total": pending + inFlight + completed + failures + shed,
            "capture_completed_total": completed, "capture_failures_total": failures,
            "capture_shed_total": shed, "capture_pending": pending,
            "capture_in_flight": inFlight, "capture_queue_capacity": 512,
            "capture_accepting": true, "capture_conserved": true,
        ]
        if let oldest { raw["capture_oldest_outstanding_age_seconds"] = oldest }
        if let active { raw["capture_active_operation_age_seconds"] = active }
        for key in omissions { raw.removeValue(forKey: key) }
        let decoder = JSONDecoder()
        decoder.nonConformingFloatDecodingStrategy = .convertFromString(
            positiveInfinity: "Infinity", negativeInfinity: "-Infinity", nan: "NaN"
        )
        return try decoder.decode(HeartbeatSnapshot.AlertEvidenceBudget.self,
                                  from: JSONSerialization.data(withJSONObject: raw))
    }

    @Test("Queue and active-operation responsiveness targets are independent of conservation")
    func pendingHealth() throws {
        for age in [0, 0.1, 45, 90] {
            let queued = try status(oldest: age)
            #expect(queued.captureConservationMaintained == true)
            #expect(!queued.captureDegraded)
        }
        let active = try status(pending: 0, inFlight: 1, oldest: 90, active: 45)
        #expect(!active.captureDegraded)
        let overdueQueue = try status(oldest: 90.001)
        #expect(overdueQueue.captureBacklogOverdue == true)
        #expect(overdueQueue.captureDegraded)
        let overdueActive = try status(pending: 0, inFlight: 1, oldest: 46, active: 46)
        #expect(overdueActive.captureBacklogOverdue == true)
        #expect(overdueActive.captureDegraded)
        let settled = try status(pending: 0, completed: 1)
        #expect(!settled.captureDegraded)
        #expect(try status(pending: 0, failures: 1).captureDegraded)
        #expect(try status(pending: 0, shed: 1).captureDegraded)
    }

    @Test("Missing, nonfinite and inconsistent capture ages fail visibly")
    func unknownTiming() throws {
        let invalid: [Any?] = [nil, -1, "NaN", "Infinity", "-Infinity"]
        for value in invalid {
            let queued = try status(oldest: value)
            #expect(queued.captureBacklogOverdue == nil)
            #expect(queued.captureDegraded)
            let active = try status(pending: 0, inFlight: 1, oldest: 1, active: value)
            #expect(active.captureDegraded)
        }
        #expect(try !status(pending: 0, oldest: nil, active: nil).captureDegraded)
        #expect(try status(pending: 0, oldest: 1).captureDegraded)
        #expect(try status(oldest: 0, active: 1).captureDegraded)
        #expect(try status(oldest: 1, active: 1).captureDegraded)
        #expect(try status(pending: 0, inFlight: 2).captureDegraded)
        #expect(try status(pending: -1).captureDegraded)
        #expect(try status(pending: 513).captureDegraded)
        #expect(try status(omissions: ["capture_conserved"]).captureDegraded)
    }
}
