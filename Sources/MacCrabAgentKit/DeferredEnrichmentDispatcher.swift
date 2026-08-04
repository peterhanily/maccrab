import Foundation
import MacCrabCore

struct DeferredEnrichmentShutdownResult: Sendable {
    let plane: HeavyEnrichmentPlaneSnapshot
    let buffer: DeferredEnrichmentBufferSnapshot

    var clean: Bool {
        !plane.accepting
            && plane.cleanlyDrained
            && plane.deferredResults == 0
            && plane.requestsConserved
            && plane.physicalCapacityConserved
            && !buffer.acceptingReservations
            && buffer.cleanlyDrained
            && buffer.reservationConserved
            && buffer.slotsConserved
            && buffer.eventsConserved
            && buffer.patchesConserved
            && buffer.withinCapacity
    }
}

/// Transfers identity-bound terminal patches from EventEnricher into the one
/// reviewed rule-match dispatcher. Calls are safe from both ingestion lanes and
/// the quiet-period timer: DeferredEnrichmentBuffer grants only one drain claim.
enum DeferredEnrichmentDispatcher {
    // Equal to the plane's entire outstanding-result bound so every terminal
    // component currently available for one event lands in the same replay
    // batch, even when other events completed around it.
    static let drainBatchLimit = DeferredEnrichmentBuffer.productionCapacity

    /// Drains every result currently available, bounded by the plane/buffer's
    /// shared 512-result ownership. A later worker completion is picked up by an
    /// event-boundary call or the short periodic timer.
    static func drainAvailable(state: DaemonState) async {
        while true {
            let claim = await state.deferredEnrichmentBuffer.claimDrainCapacity(
                limit: drainBatchLimit
            )
            guard claim > 0 else { return }
            let patches = await state.enricher.drainDeferredEnrichments(limit: claim)
            let batches = await state.deferredEnrichmentBuffer.acceptDrained(patches)
            await dispatch(batches, state: state)
            if patches.count < claim { return }
        }
    }

    /// Applies all patches already waiting on the original event, used after the
    /// first evaluation publishes the final synchronous event revision.
    static func markReadyAndDispatch(event: Event, state: DaemonState) async {
        let batches = await state.deferredEnrichmentBuffer.markReady(event)
        await dispatch(batches, state: state)
    }

    /// Terminal boundary after producers, ingestion consumers, and their timer
    /// have stopped. Heavy admission seals first, every accepted request obtains
    /// a terminal patch, and those patches are drained before alert/output lanes
    /// or persistence are sealed by the outer shutdown coordinator.
    static func shutdown(
        state: DaemonState,
        deadlineSeconds: TimeInterval
    ) async -> DeferredEnrichmentShutdownResult {
        await state.deferredEnrichmentBuffer.seal()
        _ = await state.enricher.shutdownHeavyEnrichment(
            deadlineSeconds: max(0, deadlineSeconds)
        )
        await drainAvailable(state: state)
        let plane = await state.enricher.heavyEnrichmentSnapshot()
        let buffer = await state.deferredEnrichmentBuffer.snapshot()
        return DeferredEnrichmentShutdownResult(plane: plane, buffer: buffer)
    }

    private static func dispatch(
        _ batches: [DeferredEnrichmentReplayBatch],
        state: DaemonState
    ) async {
        for batch in batches {
            if !batch.completedComponents.isEmpty {
                var matches = await state.ruleEngine.reevaluate(
                    batch.event,
                    forCompleted: batch.completedComponents
                )
                let sequenceMatches = await state.sequenceEngine.reevaluate(
                    batch.event,
                    forCompleted: batch.completedComponents
                )
                matches.append(contentsOf: sequenceMatches)
                await EventLoop.dispatchReviewedMatches(
                    state: state,
                    event: batch.event,
                    primaryMatches: matches,
                    sequenceMatches: sequenceMatches
                )
            }

            // events.db treats an event UUID as immutable evidence. Pending
            // revisions are therefore withheld on the first pass and the one
            // explicit terminal revision is offered here, including honest
            // timed_out/cancelled/unavailable coverage when no rule can replay.
            if batch.terminal {
                await state.eventWriter.enqueue(batch.event)
            }
        }
    }
}
