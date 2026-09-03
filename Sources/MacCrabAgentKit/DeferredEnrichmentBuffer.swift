import Foundation
import MacCrabCore

/// One capacity reservation made before an ingestion lane enters EventEnricher.
/// Reserving before enrichment means a pending event can always be retained;
/// saturation back-pressures the two consumers instead of dropping evidence.
struct DeferredEnrichmentReservation: Sendable, Hashable {
    fileprivate let id: UUID
    let memoryLease: EventPipelineMemoryLease

    static func == (
        lhs: DeferredEnrichmentReservation,
        rhs: DeferredEnrichmentReservation
    ) -> Bool { lhs.id == rhs.id }

    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

struct DeferredEnrichmentRetentionOutcome: Sendable {
    let hasPendingHeavyEnrichment: Bool
    /// Non-pending/rejected events remain live in EventLoop through terminal
    /// review. Keeping the source lease in that lexical scope prevents the raw
    /// Event graph from becoming unaccounted merely because no patch is pending.
    let eventLoopSourceLease: EventPipelineMemoryLease?
}

/// A single identity-bound event revision ready for dependency-filtered replay.
/// `terminal` means every accepted heavy component reached an explicit terminal
/// state. A terminal batch is persisted even when no component produced evidence.
struct DeferredEnrichmentReplayBatch: Sendable {
    let event: Event
    let completedComponents: Set<HeavyEnrichmentComponent>
    let terminal: Bool
    /// Reviewed matches accumulated since the immutable base boundary but not
    /// yet allowed to fan out. A pending-heavy Event publishes them only after
    /// the one exact terminal revision has durably settled.
    let undispatchedPrimaryMatches: [RuleMatch]
    let undispatchedSequenceMatches: [RuleMatch]
    /// Receipt for the immutable base revision admitted before any first-pass
    /// alert. Timer-driven replay runs outside EventLoop's task-local scope, so
    /// the buffer must carry the identity explicitly.
    let journalAdmission: EventJournalAdmission?
    /// Sparse base-relative terminal state composed while each predecessor raw
    /// revision was still owned. `nil` is a fail-closed composition error.
    let terminalDelta: EventTerminalDelta?
    /// ARC-shared with the actor's retained source ownership. Replay-spawned
    /// child tasks inherit this lease through TaskLocal so the raw Event graph
    /// remains charged after terminal acknowledgement removes the actor entry.
    let sourceMemoryLease: EventPipelineMemoryLease
    let appliedPatchMemoryLeases: [EventPipelineMemoryLease]
}

/// Content-free operational truth for the external half of the heavy plane.
struct DeferredEnrichmentBufferSnapshot: Sendable, Equatable {
    let acceptingReservations: Bool
    let eventCapacity: Int
    let patchCapacity: Int
    /// Source Event graphs are distinct from the sanitized prepared-handle
    /// budget. Reservations claim worst-case source credit before enrichment;
    /// retention exchanges that credit for the validator's exact estimate.
    let rawEventByteCapacity: Int
    let reservationRawEventByteCharge: Int
    let patchByteCapacity: Int
    let reservedSlots: Int
    let retainedEvents: Int
    let rejectedPendingEvents: Int
    let reservedRawEventBytes: Int
    let retainedRawEventBytes: Int
    let retainedRawEventBytesHighWatermark: Int
    let bufferedPatches: Int
    let bufferedPatchBytes: Int
    let bufferedPatchBytesHighWatermark: Int
    /// Patch payload now embedded in a retained terminal Event. The patch queue
    /// no longer owns it, but the Event graph does until replay completes.
    let appliedPatchBytes: Int
    let appliedPatchBytesHighWatermark: Int
    let orphanPatches: Int
    let waitingReservations: Int
    let drainCapacityClaimed: Int
    let drainByteCapacityClaimed: Int
    let reservationRequestsTotal: UInt64
    let reservationsGrantedTotal: UInt64
    let reservationsRejectedAfterSealTotal: UInt64
    let reservationMemoryRejectionsTotal: UInt64
    let slotsReleasedTotal: UInt64
    let retainedEventsTotal: UInt64
    let closedEventsTotal: UInt64
    let retainedRawEventBytesTotal: UInt64
    let releasedRawEventBytesTotal: UInt64
    let rawEventByteRejectionsTotal: UInt64
    let rejectedPendingEventsTotal: UInt64
    let rejectedPendingEventsClosedTotal: UInt64
    let patchesReceivedTotal: UInt64
    let patchesConsumedTotal: UInt64
    let patchBytesReceivedTotal: UInt64
    let patchBytesConsumedTotal: UInt64
    let identityRejectedPatchesTotal: UInt64

    var reservationConserved: Bool {
        reservationRequestsTotal
            == reservationsGrantedTotal
                &+ reservationsRejectedAfterSealTotal
                &+ reservationMemoryRejectionsTotal
                &+ UInt64(waitingReservations)
    }

    var slotsConserved: Bool {
        reservationsGrantedTotal
            == slotsReleasedTotal
                &+ UInt64(reservedSlots)
                &+ UInt64(retainedEvents)
    }

    var eventsConserved: Bool {
        retainedEventsTotal == closedEventsTotal &+ UInt64(retainedEvents)
    }

    var rawEventBytesConserved: Bool {
        retainedRawEventBytesTotal
            == releasedRawEventBytesTotal &+ UInt64(retainedRawEventBytes)
    }

    var patchesConserved: Bool {
        patchesReceivedTotal
            == patchesConsumedTotal &+ UInt64(bufferedPatches)
    }

    var patchBytesConserved: Bool {
        patchBytesReceivedTotal
            == patchBytesConsumedTotal
                &+ UInt64(bufferedPatchBytes)
                &+ UInt64(appliedPatchBytes)
    }

    var withinCapacity: Bool {
        reservedSlots + retainedEvents <= eventCapacity
            && bufferedPatches + drainCapacityClaimed <= patchCapacity
            && reservedRawEventBytes + retainedRawEventBytes
                <= rawEventByteCapacity
            && reservedRawEventBytes >= reservedSlots
            && reservedRawEventBytes
                <= reservedSlots * reservationRawEventByteCharge
            && bufferedPatchBytes + appliedPatchBytes
                + drainByteCapacityClaimed
                <= patchByteCapacity
    }

    var cleanlyDrained: Bool {
        reservedSlots == 0
            && retainedEvents == 0
            && rejectedPendingEvents == 0
            && bufferedPatches == 0
            && orphanPatches == 0
            && waitingReservations == 0
            && drainCapacityClaimed == 0
            && drainByteCapacityClaimed == 0
            && reservedRawEventBytes == 0
            && retainedRawEventBytes == 0
            && bufferedPatchBytes == 0
            && appliedPatchBytes == 0
    }
}

/// Bounded transfer owner between HeavyEnrichmentPlane and detection replay.
///
/// Two EventLoop lanes can enrich concurrently. A very fast worker (or the
/// quiet-period timer) can therefore drain a terminal patch before the lane has
/// published its original event. Orphans are retained by event UUID until the
/// pre-reserved event arrives; neither side evicts or overwrites on pressure.
actor DeferredEnrichmentBuffer {
    static let productionCapacity = 512
    static let productionRawEventByteCapacity = EventPipelineLiveMemoryBudget
        .productionMaximumBytes
    /// Claiming the validator's complete accepted source envelope before
    /// enrichment guarantees a later accepted source can transfer without an
    /// unaccounted suspended Event.
    // v1.22.0 MEASUREMENT PENDING (item6): this stays the flat 24 MiB
    // `maximumAcceptedSourceRetainedBytes` for every reservation today. Fix
    // design step 2 (v1.22.0 ingest-headroom brief) wants a smaller constant
    // sized from the real P99/P99.9/max pre-enrichment sourceBytes seen in
    // production traffic (see EventJournalSourceSizeTelemetry.snapshot() in
    // EventJournalAdmissionValidator.swift) — chosen with a wide safety
    // margin over that tail, since `resizeReservation()` below rejects any
    // final size above this charge. Do not lower this without that
    // measurement: too small silently turns legitimate large (but
    // non-overflow) events into a new drop path.
    static let productionReservationRawEventByteCharge =
        EventJournalAdmissionValidator.maximumAcceptedSourceRetainedBytes

    private struct Retained {
        var event: Event
        var readyForReplay: Bool
        var terminalReplayInFlight: Bool
        var patches: [BufferedPatch]
        var journalAdmission: EventJournalAdmission?
        var undispatchedPrimaryMatches: [RuleMatch]
        var undispatchedSequenceMatches: [RuleMatch]
        var terminalDelta: EventTerminalDelta?
        let rawEventByteCharge: Int
        var appliedPatchByteCharge: Int
        let sourceMemoryLease: EventPipelineMemoryLease
        var appliedPatchMemoryLeases: [EventPipelineMemoryLease]
    }

    private struct BufferedPatch {
        let patch: DeferredEventEnrichment
        let retainedByteCharge: Int
        let memoryLease: EventPipelineMemoryLease
    }

    private struct RejectedPendingEvent {
        let binding: HeavyEnrichmentBinding
        var pendingComponents: Set<HeavyEnrichmentComponent>
    }

    private struct ReservationWaiter {
        let continuation: CheckedContinuation<UUID?, Never>
    }

    private let eventCapacity: Int
    private let patchCapacity: Int
    private let rawEventByteCapacity: Int
    private let reservationRawEventByteCharge: Int
    private let patchByteCapacity: Int
    private let liveMemoryBudget: EventPipelineLiveMemoryBudget
    private var acceptingReservations = true
    private var reservations: [UUID: EventPipelineMemoryLease] = [:]
    /// Local slots waiting for process-wide credit. Counted as waiting rather
    /// than granted so both the count and request ledgers remain exact.
    private var pendingMemoryReservationIDs: Set<UUID> = []
    private var reservedRawEventBytes = 0
    private var retainedByEventID: [UUID: Retained] = [:]
    private var rejectedPendingByEventID: [UUID: RejectedPendingEvent] = [:]
    private var retainedRawEventBytes = 0
    private var retainedRawEventBytesHighWatermark = 0
    private var orphanPatchesByEventID: [UUID: [BufferedPatch]] = [:]
    private var orphanPatchCount = 0
    private var bufferedPatchBytes = 0
    private var bufferedPatchBytesHighWatermark = 0
    private var appliedPatchBytes = 0
    private var appliedPatchBytesHighWatermark = 0
    private var reservationWaiters: [ReservationWaiter] = []
    private var drainCapacityClaimed = 0
    private var drainByteCapacityClaimed = 0

    private var reservationRequestsTotal: UInt64 = 0
    private var reservationsGrantedTotal: UInt64 = 0
    private var reservationsRejectedAfterSealTotal: UInt64 = 0
    private var reservationMemoryRejectionsTotal: UInt64 = 0
    private var slotsReleasedTotal: UInt64 = 0
    private var retainedEventsTotal: UInt64 = 0
    private var closedEventsTotal: UInt64 = 0
    private var retainedRawEventBytesTotal: UInt64 = 0
    private var releasedRawEventBytesTotal: UInt64 = 0
    private var rawEventByteRejectionsTotal: UInt64 = 0
    private var rejectedPendingEventsTotal: UInt64 = 0
    private var rejectedPendingEventsClosedTotal: UInt64 = 0
    private var patchesReceivedTotal: UInt64 = 0
    private var patchesConsumedTotal: UInt64 = 0
    private var patchBytesReceivedTotal: UInt64 = 0
    private var patchBytesConsumedTotal: UInt64 = 0
    private var identityRejectedPatchesTotal: UInt64 = 0

    init(
        eventCapacity: Int = DeferredEnrichmentBuffer.productionCapacity,
        patchCapacity: Int = DeferredEnrichmentBuffer.productionCapacity,
        rawEventByteCapacity: Int = DeferredEnrichmentBuffer
            .productionRawEventByteCapacity,
        reservationRawEventByteCharge: Int = DeferredEnrichmentBuffer
            .productionReservationRawEventByteCharge,
        patchByteCapacity: Int = DeferredEnrichmentBuffer
            .productionRawEventByteCapacity,
        liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared
    ) {
        precondition(eventCapacity > 0)
        precondition(patchCapacity > 0)
        precondition(rawEventByteCapacity > 0)
        precondition(reservationRawEventByteCharge > 0)
        precondition(patchByteCapacity > 0)
        self.eventCapacity = eventCapacity
        self.patchCapacity = patchCapacity
        self.rawEventByteCapacity = rawEventByteCapacity
        self.reservationRawEventByteCharge = min(
            rawEventByteCapacity,
            reservationRawEventByteCharge
        )
        self.patchByteCapacity = patchByteCapacity
        self.liveMemoryBudget = liveMemoryBudget
    }

    /// Reserves memory ownership before enrichment. This call waits at the hard
    /// bound rather than returning a lossy rejection. In production only the two
    /// ingestion consumers can wait here, while the independent timer continues
    /// draining terminal patches and releasing retained slots.
    func reserveEventSlot() async -> DeferredEnrichmentReservation? {
        increment(&reservationRequestsTotal)
        guard acceptingReservations else {
            increment(&reservationsRejectedAfterSealTotal)
            return nil
        }
        let reservationID: UUID?
        if canClaimLocalReservation {
            reservationID = claimLocalReservation()
        } else if reservationWaiters.count < eventCapacity {
            reservationID = await withCheckedContinuation { continuation in
                reservationWaiters.append(ReservationWaiter(
                    continuation: continuation
                ))
            }
        } else {
            increment(&reservationMemoryRejectionsTotal)
            return nil
        }
        guard let reservationID else { return nil }

        // The local slot is claimed before awaiting global credit, so a waiter
        // never pins 24 MiB that the retained event ahead of it needs to finish.
        guard let lease = await liveMemoryBudget.acquire(
            bytes: reservationRawEventByteCharge,
            owner: .eventSource
        ) else {
            pendingMemoryReservationIDs.remove(reservationID)
            increment(&reservationMemoryRejectionsTotal)
            grantWaitingReservations()
            return nil
        }
        guard acceptingReservations,
              pendingMemoryReservationIDs.remove(reservationID) != nil else {
            increment(&reservationsRejectedAfterSealTotal)
            grantWaitingReservations()
            return nil
        }
        reservations[reservationID] = lease
        reservedRawEventBytes += lease.bytes
        increment(&reservationsGrantedTotal)
        return DeferredEnrichmentReservation(
            id: reservationID,
            memoryLease: lease
        )
    }

    /// Shrink the pre-enrichment worst-case R claim to the final synchronous
    /// base's structural estimate before J workspace waits. This releases real
    /// process-wide credit while keeping the reservation/count ledgers exact.
    func resizeReservation(
        _ reservation: DeferredEnrichmentReservation,
        to sourceRetainedByteEstimate: Int
    ) -> Bool {
        guard sourceRetainedByteEstimate > 0,
              sourceRetainedByteEstimate <= reservationRawEventByteCharge,
              let owned = reservations[reservation.id],
              owned === reservation.memoryLease else { return false }
        let previous = owned.bytes
        guard sourceRetainedByteEstimate <= previous,
              owned.resize(to: sourceRetainedByteEstimate) else { return false }
        reservedRawEventBytes = max(
            0,
            reservedRawEventBytes - (previous - sourceRetainedByteEstimate)
        )
        return true
    }

    /// Transfers a reservation into retained ownership only when the event has
    /// pending heavy coverage. Non-pending events release their reservation.
    @discardableResult
    func retain(
        _ event: Event,
        using reservation: DeferredEnrichmentReservation,
        journalAdmission: EventJournalAdmission? = nil,
        sourceRetainedByteEstimate: Int? = nil
    ) -> Bool {
        retainWithOwnership(
            event,
            using: reservation,
            journalAdmission: journalAdmission,
            sourceRetainedByteEstimate: sourceRetainedByteEstimate
                ?? reservation.memoryLease.bytes
        ).hasPendingHeavyEnrichment
    }

    /// Production ownership transfer. When no deferred replay is pending, the
    /// caller keeps the returned source lease until its EventLoop scope ends.
    /// Pending work transfers that same lease into this actor—never a duplicate.
    func retainWithOwnership(
        _ event: Event,
        using reservation: DeferredEnrichmentReservation,
        journalAdmission: EventJournalAdmission? = nil,
        sourceRetainedByteEstimate: Int
    ) -> DeferredEnrichmentRetentionOutcome {
        guard let ownedLease = reservations.removeValue(
            forKey: reservation.id
        ), ownedLease === reservation.memoryLease else {
            return DeferredEnrichmentRetentionOutcome(
                hasPendingHeavyEnrichment: false,
                eventLoopSourceLease: nil
            )
        }
        reservedRawEventBytes = max(
            0,
            reservedRawEventBytes - ownedLease.bytes
        )
        let rawCharge = sourceRetainedByteEstimate
        guard rawCharge > 0,
              rawCharge <= reservationRawEventByteCharge,
              ownedLease.resize(to: rawCharge) else {
            increment(&rawEventByteRejectionsTotal)
            retainRejectedPendingIdentity(event)
            consumeOrphansForRejectedPending(eventID: event.id)
            releaseSlot()
            return DeferredEnrichmentRetentionOutcome(
                hasPendingHeavyEnrichment: false,
                eventLoopSourceLease: ownedLease
            )
        }
        guard DeferredEventEnrichment.hasPendingCoverage(in: event) else {
            releaseSlot()
            return DeferredEnrichmentRetentionOutcome(
                hasPendingHeavyEnrichment: false,
                eventLoopSourceLease: ownedLease
            )
        }

        // UUID collision with a different event is a contract failure. Keep the
        // first event rather than silently replacing security evidence.
        guard retainedByEventID[event.id] == nil else {
            increment(&rawEventByteRejectionsTotal)
            releaseSlot()
            return DeferredEnrichmentRetentionOutcome(
                hasPendingHeavyEnrichment: false,
                eventLoopSourceLease: ownedLease
            )
        }
        let orphans = orphanPatchesByEventID.removeValue(forKey: event.id) ?? []
        orphanPatchCount -= orphans.count
        retainedByEventID[event.id] = Retained(
            event: event,
            readyForReplay: false,
            terminalReplayInFlight: false,
            patches: orphans,
            journalAdmission: journalAdmission,
            undispatchedPrimaryMatches: [],
            undispatchedSequenceMatches: [],
            terminalDelta: EventTerminalDelta(eventID: event.id),
            rawEventByteCharge: rawCharge,
            appliedPatchByteCharge: 0,
            sourceMemoryLease: ownedLease,
            appliedPatchMemoryLeases: []
        )
        retainedRawEventBytes += rawCharge
        retainedRawEventBytesHighWatermark = max(
            retainedRawEventBytesHighWatermark,
            retainedRawEventBytes
        )
        add(UInt64(rawCharge), to: &retainedRawEventBytesTotal)
        increment(&retainedEventsTotal)
        return DeferredEnrichmentRetentionOutcome(
            hasPendingHeavyEnrichment: true,
            // ARC shares one credit with Retained; this extra reference keeps
            // the same (not double-charged) lease alive while EventLoop still
            // owns its local raw Event value.
            eventLoopSourceLease: ownedLease
        )
    }

    /// Publishes the final synchronous EventLoop revision after the initial
    /// detection pass. Patches that won the two-lane race are applied as one
    /// batch now; replay can never overtake the event's first evaluation.
    func markReady(
        _ event: Event,
        initialPrimaryMatches: [RuleMatch] = [],
        initialSequenceMatches: [RuleMatch] = []
    ) -> [DeferredEnrichmentReplayBatch] {
        guard var retained = retainedByEventID[event.id] else { return [] }
        guard !retained.terminalReplayInFlight else { return [] }
        guard HeavyEnrichmentBinding(event: retained.event).matches(event) else {
            return []
        }
        retained.terminalDelta = composeTerminalDelta(
            retained.terminalDelta,
            from: retained.event,
            to: event
        )
        retained.event = event
        retained.undispatchedPrimaryMatches = ReviewedRuleMatches.merged(
            retained.undispatchedPrimaryMatches,
            initialPrimaryMatches
        )
        retained.undispatchedSequenceMatches = ReviewedRuleMatches.merged(
            retained.undispatchedSequenceMatches,
            initialSequenceMatches
        )
        retained.readyForReplay = true
        retainedByEventID[event.id] = retained
        return consumeBufferedPatches(for: event.id)
    }

    /// Releases terminal replay ownership only after rule review, alert
    /// dispatch, and terminal-journal enqueue have all returned. Until this
    /// acknowledgement the raw Event graph remains inside both the count and
    /// byte gauges even though a Sendable value crossed to the dispatcher.
    func completeTerminalReplay(eventID: UUID) {
        guard let retained = retainedByEventID[eventID],
              retained.terminalReplayInFlight else { return }
        retainedByEventID.removeValue(forKey: eventID)
        increment(&closedEventsTotal)
        releaseRetainedSlot(
            bytes: retained.rawEventByteCharge,
            appliedPatchBytes: retained.appliedPatchByteCharge
        )
    }

    /// Carry reviewed matches from a non-terminal replay into the retained
    /// revision so later component completion order cannot change the final
    /// terminal overlay. Storage promotion independently unions the same set.
    func mergeReviewedMatches(
        eventID: UUID,
        event: Event,
        primaryMatches: [RuleMatch],
        sequenceMatches: [RuleMatch]
    ) {
        guard var retained = retainedByEventID[eventID] else { return }
        guard HeavyEnrichmentBinding(event: retained.event).matches(event)
        else { return }
        retained.terminalDelta = composeTerminalDelta(
            retained.terminalDelta,
            from: retained.event,
            to: event
        )
        retained.event = event
        retained.undispatchedPrimaryMatches = ReviewedRuleMatches.merged(
            retained.undispatchedPrimaryMatches,
            primaryMatches
        )
        retained.undispatchedSequenceMatches = ReviewedRuleMatches.merged(
            retained.undispatchedSequenceMatches,
            sequenceMatches
        )
        retainedByEventID[eventID] = retained
    }

    /// Claims bounded space before a caller removes results from the core plane.
    /// Only one drain may be in flight; the claim covers the actor reentrancy gap
    /// while awaiting HeavyEnrichmentPlane.
    func claimDrainCapacity(limit: Int) -> Int {
        guard limit > 0, drainCapacityClaimed == 0 else { return 0 }
        let available = max(0, patchCapacity - bufferedPatchCount)
        let availableBytes = max(
            0,
            patchByteCapacity - min(
                patchByteCapacity,
                bufferedPatchBytes + appliedPatchBytes
            )
        )
        guard available > 0, availableBytes > 0 else { return 0 }
        let claim = min(limit, available)
        drainCapacityClaimed = claim
        drainByteCapacityClaimed = availableBytes
        return claim
    }

    func claimedDrainByteCapacity() -> Int {
        drainByteCapacityClaimed
    }

    /// Accepts the exact prefix removed under `claimDrainCapacity`. Every patch
    /// is either buffered against a retained event, held as a bounded orphan, or
    /// consumed into an identity-checked event revision.
    func acceptDrained(
        _ patches: [DeferredEventEnrichment]
    ) -> [DeferredEnrichmentReplayBatch] {
        let owned = patches.compactMap { patch -> OwnedDeferredEventEnrichment? in
            guard let lease = liveMemoryBudget.tryAcquire(
                bytes: patch.retainedByteEstimate,
                owner: .deferredPatch
            ) else {
                increment(&identityRejectedPatchesTotal)
                return nil
            }
            return OwnedDeferredEventEnrichment(
                patch: patch,
                memoryLease: lease
            )
        }
        return acceptOwnedDrained(owned, originalCount: patches.count)
    }

    /// Production transfer from HeavyEnrichmentPlane. Each patch arrives with
    /// the exact lease that already covered it; changing H -> P is a category
    /// transfer and leaves the process-wide aggregate unchanged.
    func acceptOwnedDrained(
        _ patches: [OwnedDeferredEventEnrichment]
    ) -> [DeferredEnrichmentReplayBatch] {
        acceptOwnedDrained(patches, originalCount: patches.count)
    }

    private func acceptOwnedDrained(
        _ patches: [OwnedDeferredEventEnrichment],
        originalCount: Int
    ) -> [DeferredEnrichmentReplayBatch] {
        let claim = drainCapacityClaimed
        let byteClaim = drainByteCapacityClaimed
        drainCapacityClaimed = 0
        drainByteCapacityClaimed = 0
        // The core plane promises to return at most the requested limit. Make a
        // contract breach terminal instead of accepting a prefix and silently
        // losing the remainder in optimized builds.
        precondition(
            originalCount <= claim,
            "heavy enrichment drain exceeded claimed capacity"
        )
        let buffered = patches.compactMap { owned -> BufferedPatch? in
            let patch = owned.patch
            guard owned.memoryLease.bytes >= patch.retainedByteEstimate,
                  owned.memoryLease.transfer(to: .deferredPatch) else {
                increment(&identityRejectedPatchesTotal)
                return nil
            }
            return BufferedPatch(
                patch: patch,
                retainedByteCharge: patch.retainedByteEstimate,
                memoryLease: owned.memoryLease
            )
        }
        let acceptedBytes = buffered.reduce(0) { partial, item in
            let sum = partial.addingReportingOverflow(
                item.retainedByteCharge
            )
            return sum.overflow ? Int.max : sum.partialValue
        }
        precondition(
            acceptedBytes <= byteClaim,
            "heavy enrichment drain exceeded claimed byte capacity"
        )
        guard originalCount > 0 else { return [] }
        add(UInt64(originalCount), to: &patchesReceivedTotal)
        let rejectedOwnership = max(0, originalCount - buffered.count)
        add(UInt64(rejectedOwnership), to: &patchesConsumedTotal)
        add(UInt64(acceptedBytes), to: &patchBytesReceivedTotal)

        var touched: [UUID] = []
        var touchedSet: Set<UUID> = []
        for item in buffered {
            let patch = item.patch
            let eventID = patch.binding.eventID
            if var rejected = rejectedPendingByEventID[eventID] {
                if rejected.binding == patch.binding,
                   rejected.pendingComponents.remove(patch.component) != nil {
                    increment(&patchesConsumedTotal)
                    add(
                        UInt64(item.retainedByteCharge),
                        to: &patchBytesConsumedTotal
                    )
                    if rejected.pendingComponents.isEmpty {
                        rejectedPendingByEventID.removeValue(forKey: eventID)
                        increment(&rejectedPendingEventsClosedTotal)
                    } else {
                        rejectedPendingByEventID[eventID] = rejected
                    }
                } else {
                    increment(&identityRejectedPatchesTotal)
                    increment(&patchesConsumedTotal)
                    add(
                        UInt64(item.retainedByteCharge),
                        to: &patchBytesConsumedTotal
                    )
                }
                continue
            }
            if var retained = retainedByEventID[eventID] {
                retained.patches.append(item)
                retainedByEventID[eventID] = retained
            } else {
                orphanPatchesByEventID[eventID, default: []].append(item)
                orphanPatchCount += 1
            }
            bufferedPatchBytes += item.retainedByteCharge
            if touchedSet.insert(eventID).inserted { touched.append(eventID) }
        }
        bufferedPatchBytesHighWatermark = max(
            bufferedPatchBytesHighWatermark,
            bufferedPatchBytes
        )

        var batches: [DeferredEnrichmentReplayBatch] = []
        for eventID in touched {
            batches.append(contentsOf: consumeBufferedPatches(for: eventID))
        }
        return batches
    }

    func cancelDrainClaim() {
        drainCapacityClaimed = 0
        drainByteCapacityClaimed = 0
    }

    /// Seals future reservation admission. Shutdown calls this only after both
    /// ingestion consumers have joined, so a waiter here is itself unclean truth.
    func seal() {
        guard acceptingReservations else { return }
        acceptingReservations = false
        let waiters = reservationWaiters
        reservationWaiters.removeAll(keepingCapacity: false)
        add(UInt64(waiters.count), to: &reservationsRejectedAfterSealTotal)
        for waiter in waiters { waiter.continuation.resume(returning: nil) }
    }

    func snapshot() -> DeferredEnrichmentBufferSnapshot {
        DeferredEnrichmentBufferSnapshot(
            acceptingReservations: acceptingReservations,
            eventCapacity: eventCapacity,
            patchCapacity: patchCapacity,
            rawEventByteCapacity: rawEventByteCapacity,
            reservationRawEventByteCharge: reservationRawEventByteCharge,
            patchByteCapacity: patchByteCapacity,
            reservedSlots: reservations.count,
            retainedEvents: retainedByEventID.count,
            rejectedPendingEvents: rejectedPendingByEventID.count,
            reservedRawEventBytes: reservedRawEventBytes,
            retainedRawEventBytes: retainedRawEventBytes,
            retainedRawEventBytesHighWatermark:
                retainedRawEventBytesHighWatermark,
            bufferedPatches: bufferedPatchCount,
            bufferedPatchBytes: bufferedPatchBytes,
            bufferedPatchBytesHighWatermark:
                bufferedPatchBytesHighWatermark,
            appliedPatchBytes: appliedPatchBytes,
            appliedPatchBytesHighWatermark:
                appliedPatchBytesHighWatermark,
            orphanPatches: orphanPatchCount,
            waitingReservations: reservationWaiters.count
                + pendingMemoryReservationIDs.count,
            drainCapacityClaimed: drainCapacityClaimed,
            drainByteCapacityClaimed: drainByteCapacityClaimed,
            reservationRequestsTotal: reservationRequestsTotal,
            reservationsGrantedTotal: reservationsGrantedTotal,
            reservationsRejectedAfterSealTotal: reservationsRejectedAfterSealTotal,
            reservationMemoryRejectionsTotal:
                reservationMemoryRejectionsTotal,
            slotsReleasedTotal: slotsReleasedTotal,
            retainedEventsTotal: retainedEventsTotal,
            closedEventsTotal: closedEventsTotal,
            retainedRawEventBytesTotal: retainedRawEventBytesTotal,
            releasedRawEventBytesTotal: releasedRawEventBytesTotal,
            rawEventByteRejectionsTotal: rawEventByteRejectionsTotal,
            rejectedPendingEventsTotal: rejectedPendingEventsTotal,
            rejectedPendingEventsClosedTotal:
                rejectedPendingEventsClosedTotal,
            patchesReceivedTotal: patchesReceivedTotal,
            patchesConsumedTotal: patchesConsumedTotal,
            patchBytesReceivedTotal: patchBytesReceivedTotal,
            patchBytesConsumedTotal: patchBytesConsumedTotal,
            identityRejectedPatchesTotal: identityRejectedPatchesTotal
        )
    }

    private var bufferedPatchCount: Int {
        retainedByEventID.values.reduce(orphanPatchCount) { $0 + $1.patches.count }
    }

    private func consumeBufferedPatches(
        for eventID: UUID
    ) -> [DeferredEnrichmentReplayBatch] {
        guard var retained = retainedByEventID[eventID],
              retained.readyForReplay,
              !retained.terminalReplayInFlight,
              !retained.patches.isEmpty else { return [] }

        let patches = retained.patches
        retained.patches.removeAll(keepingCapacity: false)
        var event = retained.event
        var completed: Set<HeavyEnrichmentComponent> = []
        for item in patches {
            let patch = item.patch
            bufferedPatchBytes = max(
                0,
                bufferedPatchBytes - item.retainedByteCharge
            )
            let before = DeferredEventEnrichment.coverageState(
                for: patch.component,
                in: event
            )
            guard let revised = patch.applying(to: event) else {
                increment(&identityRejectedPatchesTotal)
                increment(&patchesConsumedTotal)
                add(
                    UInt64(item.retainedByteCharge),
                    to: &patchBytesConsumedTotal
                )
                if let terminalized = patch.terminalizingRejectedEvidence(
                    in: event
                ) {
                    retained.terminalDelta = composeTerminalDelta(
                        retained.terminalDelta,
                        from: event,
                        to: terminalized
                    )
                    event = terminalized
                }
                continue
            }
            retained.terminalDelta = composeTerminalDelta(
                retained.terminalDelta,
                from: event,
                to: revised
            )
            event = revised
            let applied = retained.appliedPatchByteCharge
                .addingReportingOverflow(item.retainedByteCharge)
            retained.appliedPatchByteCharge = applied.overflow
                ? Int.max : applied.partialValue
            retained.appliedPatchMemoryLeases.append(item.memoryLease)
            appliedPatchBytes += item.retainedByteCharge
            appliedPatchBytesHighWatermark = max(
                appliedPatchBytesHighWatermark,
                appliedPatchBytes
            )
            increment(&patchesConsumedTotal)
            if patch.outcome == .completed,
               before == .pending,
               DeferredEventEnrichment.coverageState(
                for: patch.component,
                in: revised
               ) == nil {
                completed.insert(patch.component)
            }
        }

        retained.event = event
        let terminal = !DeferredEventEnrichment.hasPendingCoverage(in: event)
        if terminal {
            retained.terminalReplayInFlight = true
            retainedByEventID[eventID] = retained
        } else {
            retainedByEventID[eventID] = retained
        }

        guard terminal || !completed.isEmpty else { return [] }
        return [DeferredEnrichmentReplayBatch(
            event: event,
            completedComponents: completed,
            terminal: terminal,
            undispatchedPrimaryMatches:
                retained.undispatchedPrimaryMatches,
            undispatchedSequenceMatches:
                retained.undispatchedSequenceMatches,
            journalAdmission: retained.journalAdmission,
            terminalDelta: retained.terminalDelta,
            sourceMemoryLease: retained.sourceMemoryLease,
            appliedPatchMemoryLeases: retained.appliedPatchMemoryLeases
        )]
    }

    private func composeTerminalDelta(
        _ current: EventTerminalDelta?,
        from previous: Event,
        to next: Event
    ) -> EventTerminalDelta? {
        guard let current else { return nil }
        do {
            let step = try EventTerminalDelta(base: previous, terminal: next)
            return try current.followed(by: step)
        } catch {
            // The terminal alert barrier will persist this as an admission gap;
            // never fall back to a full same-UUID rewrite or silently omit fields.
            return nil
        }
    }

    private func claimLocalReservation() -> UUID {
        let id = UUID()
        pendingMemoryReservationIDs.insert(id)
        return id
    }

    private func retainRejectedPendingIdentity(_ event: Event) {
        let pending = Set(DeferredEventEnrichment.coverage(in: event).compactMap {
            component, coverage in
            coverage == .pending ? component : nil
        })
        guard !pending.isEmpty,
              rejectedPendingByEventID[event.id] == nil else { return }
        rejectedPendingByEventID[event.id] = RejectedPendingEvent(
            binding: HeavyEnrichmentBinding(event: event),
            pendingComponents: pending
        )
        increment(&rejectedPendingEventsTotal)
    }

    /// A fast worker may publish an orphan before the source Event fails raw
    /// ownership admission. Once only the compact rejected identity remains,
    /// consume that already-buffered patch immediately; otherwise it can never
    /// attach to an Event and would hold bytes forever.
    private func consumeOrphansForRejectedPending(eventID: UUID) {
        guard var rejected = rejectedPendingByEventID[eventID],
              let orphans = orphanPatchesByEventID.removeValue(
                forKey: eventID
              ) else { return }
        orphanPatchCount = max(0, orphanPatchCount - orphans.count)
        for item in orphans {
            bufferedPatchBytes = max(
                0,
                bufferedPatchBytes - item.retainedByteCharge
            )
            if rejected.binding == item.patch.binding,
               rejected.pendingComponents.remove(item.patch.component) != nil {
                // Conserved terminal result for evidence we deliberately could
                // not retain under the source-graph byte ceiling.
            } else {
                increment(&identityRejectedPatchesTotal)
            }
            increment(&patchesConsumedTotal)
            add(
                UInt64(item.retainedByteCharge),
                to: &patchBytesConsumedTotal
            )
        }
        if rejected.pendingComponents.isEmpty {
            rejectedPendingByEventID.removeValue(forKey: eventID)
            increment(&rejectedPendingEventsClosedTotal)
        } else {
            rejectedPendingByEventID[eventID] = rejected
        }
    }

    private func releaseSlot() {
        increment(&slotsReleasedTotal)
        grantWaitingReservations()
    }

    private func releaseRetainedSlot(bytes: Int, appliedPatchBytes: Int) {
        retainedRawEventBytes = max(0, retainedRawEventBytes - bytes)
        add(UInt64(max(0, bytes)), to: &releasedRawEventBytesTotal)
        self.appliedPatchBytes = max(
            0,
            self.appliedPatchBytes - max(0, appliedPatchBytes)
        )
        add(
            UInt64(max(0, appliedPatchBytes)),
            to: &patchBytesConsumedTotal
        )
        releaseSlot()
    }

    private var canClaimLocalReservation: Bool {
        guard reservations.count + pendingMemoryReservationIDs.count
                + retainedByEventID.count < eventCapacity,
              reservationRawEventByteCharge <= rawEventByteCapacity else {
            return false
        }
        let owned = min(
            rawEventByteCapacity,
            reservedRawEventBytes + retainedRawEventBytes
                + pendingMemoryReservationIDs.count
                    * reservationRawEventByteCharge
        )
        return reservationRawEventByteCharge
            <= rawEventByteCapacity - owned
    }

    private func grantWaitingReservations() {
        while acceptingReservations, canClaimLocalReservation,
              !reservationWaiters.isEmpty {
            let waiter = reservationWaiters.removeFirst()
            waiter.continuation.resume(returning: claimLocalReservation())
        }
    }

    private func increment(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    private func add(_ amount: UInt64, to value: inout UInt64) {
        let sum = value.addingReportingOverflow(amount)
        value = sum.overflow ? UInt64.max : sum.partialValue
    }
}
