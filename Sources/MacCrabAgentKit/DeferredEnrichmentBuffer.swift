import Foundation
import MacCrabCore

/// One capacity reservation made before an ingestion lane enters EventEnricher.
/// Reserving before enrichment means a pending event can always be retained;
/// saturation back-pressures the two consumers instead of dropping evidence.
struct DeferredEnrichmentReservation: Sendable, Hashable {
    fileprivate let id: UUID
}

/// A single identity-bound event revision ready for dependency-filtered replay.
/// `terminal` means every accepted heavy component reached an explicit terminal
/// state. A terminal batch is persisted even when no component produced evidence.
struct DeferredEnrichmentReplayBatch: Sendable {
    let event: Event
    let completedComponents: Set<HeavyEnrichmentComponent>
    let terminal: Bool
}

/// Content-free operational truth for the external half of the heavy plane.
struct DeferredEnrichmentBufferSnapshot: Sendable, Equatable {
    let acceptingReservations: Bool
    let eventCapacity: Int
    let patchCapacity: Int
    let reservedSlots: Int
    let retainedEvents: Int
    let bufferedPatches: Int
    let orphanPatches: Int
    let waitingReservations: Int
    let drainCapacityClaimed: Int
    let reservationRequestsTotal: UInt64
    let reservationsGrantedTotal: UInt64
    let reservationsRejectedAfterSealTotal: UInt64
    let slotsReleasedTotal: UInt64
    let retainedEventsTotal: UInt64
    let closedEventsTotal: UInt64
    let patchesReceivedTotal: UInt64
    let patchesConsumedTotal: UInt64
    let identityRejectedPatchesTotal: UInt64

    var reservationConserved: Bool {
        reservationRequestsTotal
            == reservationsGrantedTotal
                &+ reservationsRejectedAfterSealTotal
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

    var patchesConserved: Bool {
        patchesReceivedTotal
            == patchesConsumedTotal &+ UInt64(bufferedPatches)
    }

    var withinCapacity: Bool {
        reservedSlots + retainedEvents <= eventCapacity
            && bufferedPatches + drainCapacityClaimed <= patchCapacity
    }

    var cleanlyDrained: Bool {
        reservedSlots == 0
            && retainedEvents == 0
            && bufferedPatches == 0
            && orphanPatches == 0
            && waitingReservations == 0
            && drainCapacityClaimed == 0
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

    private struct Retained {
        var event: Event
        var readyForReplay: Bool
        var patches: [DeferredEventEnrichment]
    }

    private struct ReservationWaiter {
        let continuation: CheckedContinuation<DeferredEnrichmentReservation?, Never>
    }

    private let eventCapacity: Int
    private let patchCapacity: Int
    private var acceptingReservations = true
    private var reservations: Set<UUID> = []
    private var retainedByEventID: [UUID: Retained] = [:]
    private var orphanPatchesByEventID: [UUID: [DeferredEventEnrichment]] = [:]
    private var orphanPatchCount = 0
    private var reservationWaiters: [ReservationWaiter] = []
    private var drainCapacityClaimed = 0

    private var reservationRequestsTotal: UInt64 = 0
    private var reservationsGrantedTotal: UInt64 = 0
    private var reservationsRejectedAfterSealTotal: UInt64 = 0
    private var slotsReleasedTotal: UInt64 = 0
    private var retainedEventsTotal: UInt64 = 0
    private var closedEventsTotal: UInt64 = 0
    private var patchesReceivedTotal: UInt64 = 0
    private var patchesConsumedTotal: UInt64 = 0
    private var identityRejectedPatchesTotal: UInt64 = 0

    init(
        eventCapacity: Int = DeferredEnrichmentBuffer.productionCapacity,
        patchCapacity: Int = DeferredEnrichmentBuffer.productionCapacity
    ) {
        precondition(eventCapacity > 0)
        precondition(patchCapacity > 0)
        self.eventCapacity = eventCapacity
        self.patchCapacity = patchCapacity
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
        if reservations.count + retainedByEventID.count < eventCapacity {
            return grantReservation()
        }
        return await withCheckedContinuation { continuation in
            reservationWaiters.append(ReservationWaiter(continuation: continuation))
        }
    }

    /// Transfers a reservation into retained ownership only when the event has
    /// pending heavy coverage. Non-pending events release their reservation.
    @discardableResult
    func retain(
        _ event: Event,
        using reservation: DeferredEnrichmentReservation
    ) -> Bool {
        guard reservations.remove(reservation.id) != nil else { return false }
        guard DeferredEventEnrichment.hasPendingCoverage(in: event) else {
            releaseSlot()
            return false
        }

        // UUID collision with a different event is a contract failure. Keep the
        // first event rather than silently replacing security evidence.
        guard retainedByEventID[event.id] == nil else {
            releaseSlot()
            return false
        }
        let orphans = orphanPatchesByEventID.removeValue(forKey: event.id) ?? []
        orphanPatchCount -= orphans.count
        retainedByEventID[event.id] = Retained(
            event: event,
            readyForReplay: false,
            patches: orphans
        )
        increment(&retainedEventsTotal)
        return true
    }

    /// Publishes the final synchronous EventLoop revision after the initial
    /// detection pass. Patches that won the two-lane race are applied as one
    /// batch now; replay can never overtake the event's first evaluation.
    func markReady(_ event: Event) -> [DeferredEnrichmentReplayBatch] {
        guard var retained = retainedByEventID[event.id] else { return [] }
        guard HeavyEnrichmentBinding(event: retained.event).matches(event) else {
            return []
        }
        retained.event = event
        retained.readyForReplay = true
        retainedByEventID[event.id] = retained
        return consumeBufferedPatches(for: event.id)
    }

    /// Claims bounded space before a caller removes results from the core plane.
    /// Only one drain may be in flight; the claim covers the actor reentrancy gap
    /// while awaiting HeavyEnrichmentPlane.
    func claimDrainCapacity(limit: Int) -> Int {
        guard limit > 0, drainCapacityClaimed == 0 else { return 0 }
        let available = max(0, patchCapacity - bufferedPatchCount)
        let claim = min(limit, available)
        drainCapacityClaimed = claim
        return claim
    }

    /// Accepts the exact prefix removed under `claimDrainCapacity`. Every patch
    /// is either buffered against a retained event, held as a bounded orphan, or
    /// consumed into an identity-checked event revision.
    func acceptDrained(
        _ patches: [DeferredEventEnrichment]
    ) -> [DeferredEnrichmentReplayBatch] {
        let claim = drainCapacityClaimed
        drainCapacityClaimed = 0
        // The core plane promises to return at most the requested limit. Make a
        // contract breach terminal instead of accepting a prefix and silently
        // losing the remainder in optimized builds.
        precondition(
            patches.count <= claim,
            "heavy enrichment drain exceeded claimed capacity"
        )
        guard !patches.isEmpty else { return [] }
        add(UInt64(patches.count), to: &patchesReceivedTotal)

        var touched: [UUID] = []
        var touchedSet: Set<UUID> = []
        for patch in patches {
            let eventID = patch.binding.eventID
            if var retained = retainedByEventID[eventID] {
                retained.patches.append(patch)
                retainedByEventID[eventID] = retained
            } else {
                orphanPatchesByEventID[eventID, default: []].append(patch)
                orphanPatchCount += 1
            }
            if touchedSet.insert(eventID).inserted { touched.append(eventID) }
        }

        var batches: [DeferredEnrichmentReplayBatch] = []
        for eventID in touched {
            batches.append(contentsOf: consumeBufferedPatches(for: eventID))
        }
        return batches
    }

    func cancelDrainClaim() {
        drainCapacityClaimed = 0
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
            reservedSlots: reservations.count,
            retainedEvents: retainedByEventID.count,
            bufferedPatches: bufferedPatchCount,
            orphanPatches: orphanPatchCount,
            waitingReservations: reservationWaiters.count,
            drainCapacityClaimed: drainCapacityClaimed,
            reservationRequestsTotal: reservationRequestsTotal,
            reservationsGrantedTotal: reservationsGrantedTotal,
            reservationsRejectedAfterSealTotal: reservationsRejectedAfterSealTotal,
            slotsReleasedTotal: slotsReleasedTotal,
            retainedEventsTotal: retainedEventsTotal,
            closedEventsTotal: closedEventsTotal,
            patchesReceivedTotal: patchesReceivedTotal,
            patchesConsumedTotal: patchesConsumedTotal,
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
              !retained.patches.isEmpty else { return [] }

        let patches = retained.patches
        retained.patches.removeAll(keepingCapacity: false)
        var event = retained.event
        var completed: Set<HeavyEnrichmentComponent> = []
        for patch in patches {
            let before = DeferredEventEnrichment.coverageState(
                for: patch.component,
                in: event
            )
            guard let revised = patch.applying(to: event) else {
                increment(&identityRejectedPatchesTotal)
                increment(&patchesConsumedTotal)
                continue
            }
            event = revised
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
            retainedByEventID.removeValue(forKey: eventID)
            increment(&closedEventsTotal)
            releaseSlot()
        } else {
            retainedByEventID[eventID] = retained
        }

        guard terminal || !completed.isEmpty else { return [] }
        return [DeferredEnrichmentReplayBatch(
            event: event,
            completedComponents: completed,
            terminal: terminal
        )]
    }

    private func grantReservation() -> DeferredEnrichmentReservation {
        let reservation = DeferredEnrichmentReservation(id: UUID())
        reservations.insert(reservation.id)
        increment(&reservationsGrantedTotal)
        return reservation
    }

    private func releaseSlot() {
        increment(&slotsReleasedTotal)
        while acceptingReservations,
              reservations.count + retainedByEventID.count < eventCapacity,
              !reservationWaiters.isEmpty {
            let waiter = reservationWaiters.removeFirst()
            waiter.continuation.resume(returning: grantReservation())
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
