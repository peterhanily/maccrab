import Foundation
import Testing
@testable import MacCrabApp

@MainActor
@Suite("Mutation confirmation scheduling")
struct V2MutationConfirmationLoopTests {
    @MainActor
    private final class Probe {
        var tracker = V2MutationTracker()
        var reads: [String] = []
        var observations: [String] = []
        var batches = 0
        var blockFirstRead = false
        var blockedRead: CheckedContinuation<Void, Never>?

        init(_ requests: [V2MutationRequest]) {
            for request in requests {
                _ = tracker.begin(request)
                tracker.submitted(request, result: .queued)
            }
        }

        func nextBatch() -> [V2MutationRequest] {
            batches += 1
            return tracker.confirmationBatch.map(\.request)
        }

        func confirm(_ request: V2MutationRequest) async -> V2MutationConfirmation {
            reads.append(request.targetID)
            if blockFirstRead && reads.count == 1 {
                // An already-issued SQLite actor read can finish after its
                // requesting view is cancelled. Release it explicitly below.
                await withCheckedContinuation { blockedRead = $0 }
            }
            return .applied
        }

        func observed(_ request: V2MutationRequest, _ result: V2MutationConfirmation) {
            observations.append(request.targetID)
            tracker.observed(request, confirmation: result)
        }

        func releaseRead() {
            blockedRead?.resume()
            blockedRead = nil
        }
    }

    private func request(_ id: String) -> V2MutationRequest {
        .init(operation: .suppressAlert, targetID: id, title: id)
    }

    private func waitUntil(_ predicate: () -> Bool) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while !predicate(), clock.now < deadline {
            try? await Task.sleep(for: .milliseconds(1))
        }
        return predicate()
    }

    @Test("refresh cancellation does not starve later batches or bulk Undo")
    func progressesIndependentlyOfTableRefresh() async throws {
        let requests = (0..<101).map { request("alert-\($0)") }
        let probe = Probe(requests)
        let loop = V2MutationConfirmationLoop(interval: .milliseconds(1))
        let confirmations = Task {
            await loop.run(nextBatch: probe.nextBatch, confirm: probe.confirm,
                           observed: probe.observed)
        }
        defer { confirmations.cancel() }

        // A table-refresh task can be cancelled at every tick while its reads
        // are still pending. Confirmation has a separate lifetime and must
        // reach the 101st request beyond its first bounded batch.
        for _ in 0..<4 {
            let tableRefresh = Task {
                try? await Task.sleep(for: .seconds(30))
            }
            tableRefresh.cancel()
            await tableRefresh.value
        }
        let applied = await waitUntil { probe.tracker.allApplied(requests) }
        confirmations.cancel()
        await confirmations.value
        #expect(applied)
        #expect(probe.batches >= 2)
        #expect(probe.reads.count == 101)
        #expect(Set(probe.reads).count == 101)
        #expect(probe.tracker.pending.isEmpty)
    }

    @Test("a provider replacement joins an in-flight read before starting its own batch")
    func replacementIsSingleFlight() async throws {
        let loop = V2MutationConfirmationLoop(interval: .seconds(30))
        let old = Probe([request("old-1"), request("old-2")])
        old.blockFirstRead = true
        let previous = Task {
            await loop.run(nextBatch: old.nextBatch, confirm: old.confirm,
                           observed: old.observed)
        }
        defer { previous.cancel(); old.releaseRead() }
        let firstStarted = await waitUntil { old.blockedRead != nil }
        try #require(firstStarted)

        let current = Probe([request("current")])
        var replacementEntered = false
        let replacement = Task {
            replacementEntered = true
            await loop.run(nextBatch: current.nextBatch, confirm: current.confirm,
                           observed: current.observed)
        }
        defer { replacement.cancel() }
        let entered = await waitUntil { replacementEntered }
        try #require(entered)
        #expect(current.reads.isEmpty)
        old.releaseRead()
        await previous.value
        let observed = await waitUntil { current.observations == ["current"] }
        replacement.cancel()
        await replacement.value
        #expect(observed)
        #expect(old.reads.count == 1)
        #expect(old.observations.isEmpty)
        #expect(current.reads == ["current"])
    }

    @Test("view cancellation discards a late result and starts no follow-on reads")
    func teardownStopsAfterCurrentRead() async throws {
        let probe = Probe([request("first"), request("second")])
        probe.blockFirstRead = true
        let loop = V2MutationConfirmationLoop(interval: .milliseconds(1))
        let visibleTask = Task {
            await loop.run(nextBatch: probe.nextBatch, confirm: probe.confirm,
                           observed: probe.observed)
        }
        defer { visibleTask.cancel(); probe.releaseRead() }
        let started = await waitUntil { probe.blockedRead != nil }
        try #require(started)
        visibleTask.cancel()
        probe.releaseRead()
        await visibleTask.value
        #expect(probe.reads.count == 1)
        #expect(probe.observations.isEmpty)
        #expect(probe.batches == 1)
    }
}
