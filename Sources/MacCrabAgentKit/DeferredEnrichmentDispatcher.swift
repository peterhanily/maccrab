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
            && plane.resultByteCapacityConserved
            && !buffer.acceptingReservations
            && buffer.cleanlyDrained
            && buffer.reservationConserved
            && buffer.slotsConserved
            && buffer.eventsConserved
            && buffer.rawEventBytesConserved
            && buffer.patchesConserved
            && buffer.patchBytesConserved
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
            let byteClaim = await state.deferredEnrichmentBuffer
                .claimedDrainByteCapacity()
            let patches = await state.enricher.drainOwnedDeferredEnrichments(
                limit: claim,
                maximumBytes: byteClaim
            )
            let batches = await state.deferredEnrichmentBuffer
                .acceptOwnedDrained(patches)
            await dispatch(batches, state: state)
            if patches.count < claim { return }
        }
    }

    /// Applies all patches already waiting on the original event, used after the
    /// first evaluation publishes the final synchronous event revision.
    static func markReadyAndDispatch(
        event: Event,
        initialPrimaryMatches: [RuleMatch],
        initialSequenceMatches: [RuleMatch],
        state: DaemonState
    ) async {
        let batches = await state.deferredEnrichmentBuffer.markReady(
            event,
            initialPrimaryMatches: initialPrimaryMatches,
            initialSequenceMatches: initialSequenceMatches
        )
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
            await EventJournalAdmissionContext.$sourceMemoryLease.withValue(
                batch.sourceMemoryLease
            ) {
                await EventJournalAdmissionContext
                    .$deferredPatchMemoryLeases.withValue(
                        batch.appliedPatchMemoryLeases
                    ) {
                    await EventJournalAdmissionContext.$current.withValue(
                        batch.journalAdmission
                    ) {
                var terminalEvent = batch.event
                var newlyReviewed = EventLoop.ReviewedMatchDispatch(
                    event: terminalEvent,
                    primaryMatches: [],
                    sequenceMatches: []
                )
                if !batch.completedComponents.isEmpty {
                    var matches = await state.ruleEngine.reevaluate(
                        terminalEvent,
                        forCompleted: batch.completedComponents
                    )
                    let sequenceMatches = await state.sequenceEngine.reevaluate(
                        terminalEvent,
                        forCompleted: batch.completedComponents
                    )
                    matches.append(contentsOf: sequenceMatches)
                    newlyReviewed = EventLoop.prepareReviewedMatches(
                        state: state,
                        event: terminalEvent,
                        primaryMatches: matches,
                        sequenceMatches: sequenceMatches
                    )
                    terminalEvent = newlyReviewed.event
                    if !batch.terminal {
                        await state.deferredEnrichmentBuffer.mergeReviewedMatches(
                            eventID: terminalEvent.id,
                            event: terminalEvent,
                            primaryMatches: newlyReviewed.primaryMatches,
                            sequenceMatches: newlyReviewed.sequenceMatches
                        )
                    }
                }

                // The immutable base was admitted before every first-pass
                // alert. Pending-heavy reviewed matches remain undispatched
                // until this exact one terminal value settles, so neither an
                // alert nor sparse promotion can overtake canonical evidence.
                if batch.terminal {
                    let primaryMatches = ReviewedRuleMatches.merged(
                        batch.undispatchedPrimaryMatches,
                        newlyReviewed.primaryMatches
                    )
                    let sequenceMatches = ReviewedRuleMatches.merged(
                        batch.undispatchedSequenceMatches,
                        newlyReviewed.sequenceMatches
                    )
                    let terminalDelta: EventTerminalDelta?
                    do {
                        let reviewedStep = try EventTerminalDelta(
                            base: batch.event,
                            terminal: terminalEvent
                        )
                        terminalDelta = try batch.terminalDelta?
                            .followed(by: reviewedStep)
                    } catch {
                        terminalDelta = nil
                    }
                    let terminalAdmission = await EventLoop
                        .settleTerminalJournalDelta(
                        terminalDelta,
                        eventID: terminalEvent.id,
                        lane: EventPipelineLane.finalLane(for: terminalEvent),
                        admission: batch.journalAdmission,
                        state: state
                    )
                    let reviewedTerminal = EventLoop.ReviewedMatchDispatch(
                        event: terminalEvent,
                        primaryMatches: primaryMatches,
                        sequenceMatches: sequenceMatches
                    )
                    terminalEvent = await EventJournalAdmissionContext
                        .$terminalRevision.withValue(terminalAdmission) {
                            await EventLoop.dispatchReviewedMatches(
                                state: state,
                                reviewed: reviewedTerminal
                            )
                        }
                }
                }
                }
            }
            if batch.terminal {
                await state.deferredEnrichmentBuffer.completeTerminalReplay(
                    eventID: batch.event.id
                )
            }
        }
    }
}
