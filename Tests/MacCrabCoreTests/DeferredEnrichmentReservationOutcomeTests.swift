import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// A lane consumer ends only when reservation admission is sealed. A memory
/// refusal is transient and must be distinguishable, or the lane stops for good.
@Suite("Deferred enrichment reservation outcomes")
struct DeferredEnrichmentReservationOutcomeTests {
    private func budget() -> EventPipelineLiveMemoryBudget {
        EventPipelineLiveMemoryBudget(
            maximumBytes: EventPipelineLiveMemoryBudget.productionMaximumBytes,
            forwardProgressReserveBytes: EventPipelineLiveMemoryBudget.productionForwardProgressReserveBytes,
            eventStoreWorkspaceReserveBytes: EventPipelineLiveMemoryBudget.productionEventStoreWorkspaceReserveBytes,
            compactReceiptReserveBytes: EventPipelineLiveMemoryBudget.productionCompactReceiptReserveBytes)
    }

    @Test("a full waiter list is a memory refusal, not a seal; seal is terminal")
    func memoryRefusalIsNotSeal() async throws {
        let buffer = DeferredEnrichmentBuffer(eventCapacity: 1, patchCapacity: 8,
                                              liveMemoryBudget: budget())
        guard case .reserved = await buffer.reserveEventSlotOutcome() else {
            Issue.record("the only slot must be granted"); return
        }
        // The second request waits for the slot. Probe only once it is queued:
        // a probe that queued first would itself wait until seal.
        let waiting = Task { await buffer.reserveEventSlotOutcome() }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(30))
        while await buffer.snapshot().waitingReservations < 1, clock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        guard await buffer.snapshot().waitingReservations == 1 else {
            Issue.record("the second request never queued")
            await buffer.seal()
            return
        }
        guard case .memoryRejected = await buffer.reserveEventSlotOutcome() else {
            Issue.record("a full waiter list must report a memory refusal")
            await buffer.seal()
            return
        }
        await buffer.seal()
        guard case .sealed = await waiting.value else {
            Issue.record("a waiter released by seal must report sealed"); return
        }
        guard case .sealed = await buffer.reserveEventSlotOutcome() else {
            Issue.record("requests after seal must report sealed"); return
        }
    }

    @Test("a replay forces a gap status only from its own admission, never the draining lane's")
    func replayStatusIsPerEvent() async throws {
        #expect(DeferredEnrichmentDispatcher.replayForcedStatus(admission: nil) == .dropped)
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabAgentKit/DeferredEnrichmentDispatcher.swift"))
        let dispatch = try #require(source.range(of: "private static func dispatch("))
        let body = source[dispatch.lowerBound...]
        let forced = try #require(body.range(of: ".withForcedNonverifiedStatus("))
        let admission = try #require(body.range(of: ".withAdmission("))
        #expect(forced.lowerBound < admission.lowerBound,
                "every replay must rebind the forced status before its admission scope")
        #expect(body.contains("replayForcedStatus(admission: batch.journalAdmission)"))
    }
}
