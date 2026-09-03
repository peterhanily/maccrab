import Foundation

/// Mutually exclusive ownership buckets under the one process-wide event
/// pipeline memory envelope. Moving evidence between pipeline stages transfers
/// a lease; it never acquires a second charge for the same retained value.
public enum EventPipelineMemoryOwner: String, CaseIterable, Sendable {
    case journalPrepared = "journal_prepared"
    case eventSource = "event_source"
    case deferredPatch = "deferred_patch"
    case heavyResult = "heavy_result"
    case eventStoreWorkspace = "event_store_workspace"
}

public struct EventPipelineLiveMemorySnapshot: Sendable, Equatable {
    public let currentBytes: Int
    public let highWatermarkBytes: Int
    public let maximumBytes: Int
    public let forwardProgressReserveBytes: Int
    public let eventStoreWorkspaceReserveBytes: Int
    public let compactReceiptReserveBytes: Int
    public let activeLeases: Int
    public let waitingAcquisitions: Int
    public let waiterHighWatermark: Int
    public let acquisitionTotal: UInt64
    public let releaseTotal: UInt64
    /// Async callers that legitimately queued for FIFO backpressure.
    public let waitsTotal: UInt64
    /// Synchronous callers that could not wait and received explicit rejection.
    public let nonblockingRejectionsTotal: UInt64
    /// Hard overload: bounded waiter storage was already full.
    public let waiterLimitSaturationsTotal: UInt64
    /// Invalid requests that can never fit under the configured envelope.
    public let oversizedRequestsTotal: UInt64
    public let cancelledWaiterTotal: UInt64
    public let bytesByOwner: [String: Int]

    public var withinCapacity: Bool {
        currentBytes >= 0 && currentBytes <= maximumBytes
            && bytesByOwner.values.reduce(0, +) == currentBytes
            && highWatermarkBytes >= currentBytes
            && highWatermarkBytes <= maximumBytes
    }

    public var leasesConserved: Bool {
        acquisitionTotal == releaseTotal &+ UInt64(activeLeases)
    }
}

/// Read-only, per-owner slice of the same counters ``EventPipelineLiveMemorySnapshot``
/// already tracks in aggregate. v1.22.0 item6: exposes the burst-time telemetry
/// needed to pick safe lease-size constants (see the MEASUREMENT PENDING markers
/// in EventJournalAdmissionValidator.swift and DeferredEnrichmentBuffer.swift).
/// Never consulted by acquisition/admission logic — instrumentation only.
public struct EventPipelineOwnerMemoryStats: Sendable, Equatable {
    /// Async callers of this owner that legitimately queued for FIFO backpressure.
    public let waitsTotal: UInt64
    /// High watermark of this owner's concurrent waiter count.
    public let waiterHighWatermark: Int
    /// Synchronous callers of this owner that could not wait and were rejected.
    public let nonblockingRejectionsTotal: UInt64
    /// This owner's requests refused because the shared bounded waiter storage
    /// was already full.
    public let waiterLimitSaturationsTotal: UInt64
    /// This owner's requests that could never fit under the configured envelope.
    public let oversizedRequestsTotal: UInt64
}

/// Reference-counted credit under ``EventPipelineLiveMemoryBudget``.
/// ARC copies share one reservation. Deinit is synchronous because receipts,
/// detached workers, and SQLite callbacks can release on any executor.
public final class EventPipelineMemoryLease: @unchecked Sendable {
    fileprivate let id: UUID
    private let budget: EventPipelineLiveMemoryBudget

    fileprivate init(id: UUID, budget: EventPipelineLiveMemoryBudget) {
        self.id = id
        self.budget = budget
    }

    public var bytes: Int { budget.bytes(for: id) }
    public var owner: EventPipelineMemoryOwner? { budget.owner(for: id) }

    /// Shrinking always succeeds. Growth is atomic and fails without changing
    /// the lease when the process-wide ceiling has no remaining credit.
    @discardableResult
    public func resize(to bytes: Int) -> Bool {
        budget.resize(id: id, to: bytes)
    }

    /// Move an already-retained value between pipeline owners with no change
    /// to the aggregate current-byte gauge.
    @discardableResult
    public func transfer(to owner: EventPipelineMemoryOwner) -> Bool {
        budget.transfer(id: id, to: owner)
    }

    /// Divide existing credit without increasing aggregate ownership. Used by
    /// timeout/cancellation: the terminal marker and uncooperative lingering
    /// worker together remain inside the operation's original reservation.
    public func split(
        bytes: Int,
        owner: EventPipelineMemoryOwner
    ) -> EventPipelineMemoryLease? {
        budget.split(id: id, bytes: bytes, owner: owner)
    }

    deinit { budget.release(id: id) }
}

/// One hard, process-wide envelope for event-pipeline retained ownership.
///
/// Production uses 96 MiB with explicit J, EventStore-workspace, and bounded
/// compact-receipt reserves. Noncritical R/P/H ownership can hold one maximum
/// 24 MiB source plus the other lane's residual source credit; a second maximum
/// source backpressures until downstream ownership releases. This is a safety
/// ceiling, not an RSS qualification allowance: the independent <=450 MiB
/// process RSS and <=64 MiB epoch-growth gates remain authoritative.
public final class EventPipelineLiveMemoryBudget: @unchecked Sendable {
    public static let productionMaximumBytes = 96 * 1_024 * 1_024
    public static let productionEventStoreWorkspaceReserveBytes =
        EventJournalCodec.maximumWorkspaceBytes
    public static let productionCompactReceiptReserveBytes =
        EventJournalPreparedOwnershipBudget.productionCompactReceiptReserveBytes
    public static let productionForwardProgressReserveBytes =
        EventJournalAdmissionValidator.maximumPreparationWorkspaceBytes
            + productionEventStoreWorkspaceReserveBytes
            + productionCompactReceiptReserveBytes
    public static let processShared = EventPipelineLiveMemoryBudget(
        maximumBytes: productionMaximumBytes,
        forwardProgressReserveBytes: productionForwardProgressReserveBytes,
        eventStoreWorkspaceReserveBytes:
            productionEventStoreWorkspaceReserveBytes,
        compactReceiptReserveBytes: productionCompactReceiptReserveBytes
    )

    /// A production-shaped envelope with independent accounting.
    ///
    /// Parallel unit fixtures are unrelated processes in production terms;
    /// giving each fixture store one of these prevents the Swift Testing
    /// runner from turning suite scheduling into synthetic pipeline pressure.
    /// Shipped components must continue to use ``processShared``. Package-only
    /// visibility keeps this seam out of the public library API.
    package static func isolatedProductionEquivalentForTesting()
        -> EventPipelineLiveMemoryBudget {
        EventPipelineLiveMemoryBudget(
            maximumBytes: productionMaximumBytes,
            forwardProgressReserveBytes: productionForwardProgressReserveBytes,
            eventStoreWorkspaceReserveBytes:
                productionEventStoreWorkspaceReserveBytes,
            compactReceiptReserveBytes: productionCompactReceiptReserveBytes
        )
    }

    private struct Reservation {
        var owner: EventPipelineMemoryOwner
        var bytes: Int
    }

    private struct Waiter {
        let id: UUID
        let bytes: Int
        let owner: EventPipelineMemoryOwner
        let continuation: CheckedContinuation<EventPipelineMemoryLease?, Never>
    }

    private let lock = NSLock()
    private let maximumBytes: Int
    private let maximumWaiters: Int
    private let forwardProgressReserveBytes: Int
    private let eventStoreWorkspaceReserveBytes: Int
    private let compactReceiptReserveBytes: Int
    private var reservations: [UUID: Reservation] = [:]
    private var currentBytes = 0
    private var highWatermarkBytes = 0
    private var bytesByOwner: [EventPipelineMemoryOwner: Int] = [:]
    private var waiters: [Waiter] = []
    private var waiterHighWatermark = 0
    private var acquisitionTotal: UInt64 = 0
    private var releaseTotal: UInt64 = 0
    private var waitsTotal: UInt64 = 0
    private var nonblockingRejectionsTotal: UInt64 = 0
    private var waiterLimitSaturationsTotal: UInt64 = 0
    private var oversizedRequestsTotal: UInt64 = 0
    private var cancelledWaiterTotal: UInt64 = 0
    // v1.22.0 item6: per-owner mirrors of the aggregate counters above,
    // updated at the same call sites under the same lock. Read-only
    // telemetry only — never consulted by acquisition/admission logic.
    private var waitsTotalByOwner: [EventPipelineMemoryOwner: UInt64] = [:]
    private var waiterHighWatermarkByOwner: [EventPipelineMemoryOwner: Int] = [:]
    private var nonblockingRejectionsTotalByOwner:
        [EventPipelineMemoryOwner: UInt64] = [:]
    private var waiterLimitSaturationsTotalByOwner:
        [EventPipelineMemoryOwner: UInt64] = [:]
    private var oversizedRequestsTotalByOwner:
        [EventPipelineMemoryOwner: UInt64] = [:]
    /// Deterministic cancellation-race seam; internal so production callers
    /// cannot make waiter delivery execute application work.
    private var waiterAssignedHookForTesting: (@Sendable () -> Void)?

    public init(
        maximumBytes: Int,
        maximumWaiters: Int = 64,
        forwardProgressReserveBytes: Int = 0,
        eventStoreWorkspaceReserveBytes: Int = 0,
        compactReceiptReserveBytes: Int = 0
    ) {
        precondition(maximumBytes > 0)
        precondition(maximumWaiters > 0)
        precondition(eventStoreWorkspaceReserveBytes >= 0)
        precondition(eventStoreWorkspaceReserveBytes <= maximumBytes)
        precondition(compactReceiptReserveBytes >= 0)
        precondition(
            eventStoreWorkspaceReserveBytes + compactReceiptReserveBytes
                <= forwardProgressReserveBytes
        )
        self.maximumBytes = maximumBytes
        self.maximumWaiters = maximumWaiters
        self.forwardProgressReserveBytes = min(
            maximumBytes,
            max(0, forwardProgressReserveBytes)
        )
        self.eventStoreWorkspaceReserveBytes =
            eventStoreWorkspaceReserveBytes
        self.compactReceiptReserveBytes = compactReceiptReserveBytes
    }

    /// Non-blocking acquisition for synchronous offer paths. Failure is an
    /// explicit backpressure/rejection outcome; no caller may allocate first
    /// and ask for credit afterward.
    public func tryAcquire(
        bytes: Int,
        owner: EventPipelineMemoryOwner
    ) -> EventPipelineMemoryLease? {
        lock.lock()
        guard bytes > 0,
              bytes <= maximumIndividualRequestBytes(for: owner) else {
            increment(&oversizedRequestsTotal)
            increment(&oversizedRequestsTotalByOwner, owner: owner)
            lock.unlock()
            return nil
        }
        // The byte check runs FIRST and the fairness gate can be bypassed by a
        // drain-side owner. Before v1.21.6-rc.33 the fairness gate was evaluated
        // first and applied unconditionally, which deadlocked the pipeline:
        // EventStore is the only participant that acquires exclusively through
        // `tryAcquire` (7 call sites, zero `acquire`), so it can never become a
        // waiter — yet it is the only actor that can finish a write and release
        // the credit the waiters are parked on. One parked waiter therefore
        // locked out the sole releaser permanently. An installed host showed
        // 46 non-blocking rejections with 36 MiB of the 96 MiB envelope free and
        // `events_storage_write_persisted_total = 0`.
        //
        // Bypassing is safe because the byte ceilings already encode the
        // carve-out this gate was trying to enforce: `maximumIndividualRequestBytes`
        // withholds `forwardProgressReserveBytes` from every source-side owner,
        // and `maximumAggregateBytes` withholds the eventStoreWorkspace reserve
        // from `.journalPrepared`. Fairness ordering adds no protection the byte
        // accounting does not already provide — it only created the inversion.
        guard canAcquireLocked(bytes: bytes, owner: owner),
              canAcquireAheadOfWaitersLocked(owner: owner)
                || isDrainSideOwner(owner) else {
            increment(&nonblockingRejectionsTotal)
            increment(&nonblockingRejectionsTotalByOwner, owner: owner)
            lock.unlock()
            return nil
        }
        let lease = createReservationLocked(bytes: bytes, owner: owner)
        lock.unlock()
        return lease
    }

    /// FIFO async acquisition for lossless pipeline boundaries. Cancellation
    /// removes the waiter and returns nil; no reservation survives the rollback.
    public func acquire(
        bytes: Int,
        owner: EventPipelineMemoryOwner
    ) async -> EventPipelineMemoryLease? {
        guard !Task.isCancelled else { return nil }
        let waiterID = UUID()
        var result: EventPipelineMemoryLease? =
            await withTaskCancellationHandler {
                await withCheckedContinuation {
                    (continuation: CheckedContinuation<
                        EventPipelineMemoryLease?, Never
                    >) in
                    self.registerAcquire(
                        id: waiterID,
                        bytes: bytes,
                        owner: owner,
                        taskIsCancelled: Task.isCancelled,
                        continuation: continuation
                    )
                }
            } onCancel: {
                self.cancelWaiter(id: waiterID)
            }
        // Cancellation can race after release assigned a lease but before this
        // continuation resumed. Drop it synchronously here so credit never
        // remains pinned until unrelated caller unwind.
        guard !Task.isCancelled else {
            if result != nil { recordAssignedWaiterCancellation() }
            result = nil
            return nil
        }
        return result
    }

    public func snapshot() -> EventPipelineLiveMemorySnapshot {
        lock.lock()
        var owners: [String: Int] = [:]
        for owner in EventPipelineMemoryOwner.allCases {
            owners[owner.rawValue] = bytesByOwner[owner, default: 0]
        }
        let value = EventPipelineLiveMemorySnapshot(
            currentBytes: currentBytes,
            highWatermarkBytes: highWatermarkBytes,
            maximumBytes: maximumBytes,
            forwardProgressReserveBytes: forwardProgressReserveBytes,
            eventStoreWorkspaceReserveBytes:
                eventStoreWorkspaceReserveBytes,
            compactReceiptReserveBytes: compactReceiptReserveBytes,
            activeLeases: reservations.count,
            waitingAcquisitions: waiters.count,
            waiterHighWatermark: waiterHighWatermark,
            acquisitionTotal: acquisitionTotal,
            releaseTotal: releaseTotal,
            waitsTotal: waitsTotal,
            nonblockingRejectionsTotal: nonblockingRejectionsTotal,
            waiterLimitSaturationsTotal: waiterLimitSaturationsTotal,
            oversizedRequestsTotal: oversizedRequestsTotal,
            cancelledWaiterTotal: cancelledWaiterTotal,
            bytesByOwner: owners
        )
        lock.unlock()
        return value
    }

    /// Read-only per-owner counters mirroring ``snapshot()``'s aggregate
    /// totals. v1.22.0 item6: lets a heartbeat publish, per owner, waits,
    /// waiter high watermark, non-blocking rejections, waiter-limit
    /// saturations, and oversized-request counts without changing any
    /// acquisition/admission behavior.
    public func perOwnerSnapshot()
        -> [EventPipelineMemoryOwner: EventPipelineOwnerMemoryStats] {
        lock.lock()
        var result: [EventPipelineMemoryOwner: EventPipelineOwnerMemoryStats] = [:]
        for owner in EventPipelineMemoryOwner.allCases {
            result[owner] = EventPipelineOwnerMemoryStats(
                waitsTotal: waitsTotalByOwner[owner, default: 0],
                waiterHighWatermark: waiterHighWatermarkByOwner[owner, default: 0],
                nonblockingRejectionsTotal:
                    nonblockingRejectionsTotalByOwner[owner, default: 0],
                waiterLimitSaturationsTotal:
                    waiterLimitSaturationsTotalByOwner[owner, default: 0],
                oversizedRequestsTotal:
                    oversizedRequestsTotalByOwner[owner, default: 0]
            )
        }
        lock.unlock()
        return result
    }

    func setWaiterAssignedHookForTesting(
        _ hook: (@Sendable () -> Void)?
    ) {
        lock.lock()
        waiterAssignedHookForTesting = hook
        lock.unlock()
    }

    fileprivate func bytes(for id: UUID) -> Int {
        lock.lock()
        let value = reservations[id]?.bytes ?? 0
        lock.unlock()
        return value
    }

    fileprivate func owner(for id: UUID) -> EventPipelineMemoryOwner? {
        lock.lock()
        let value = reservations[id]?.owner
        lock.unlock()
        return value
    }

    fileprivate func resize(id: UUID, to requestedBytes: Int) -> Bool {
        let newBytes = max(0, requestedBytes)
        var resumptions: [(CheckedContinuation<EventPipelineMemoryLease?, Never>, EventPipelineMemoryLease?)] = []
        lock.lock()
        guard var reservation = reservations[id] else {
            lock.unlock()
            return false
        }
        guard newBytes <= maximumIndividualRequestBytes(
            for: reservation.owner
        ) else {
            increment(&oversizedRequestsTotal)
            increment(&oversizedRequestsTotalByOwner, owner: reservation.owner)
            lock.unlock()
            return false
        }
        let delta = newBytes - reservation.bytes
        // Growth is a nonblocking acquisition and may not bypass an older FIFO
        // waiter. Production preparation reserves its maximum up front, so all
        // hot-path resize operations are transfers/shrinks.
        guard delta <= 0 || (
            canAcquireAheadOfWaitersLocked(owner: reservation.owner)
                && canAcquireLocked(bytes: delta, owner: reservation.owner)
        ) else {
            increment(&nonblockingRejectionsTotal)
            increment(&nonblockingRejectionsTotalByOwner, owner: reservation.owner)
            lock.unlock()
            return false
        }
        currentBytes += delta
        bytesByOwner[reservation.owner, default: 0] += delta
        reservation.bytes = newBytes
        reservations[id] = reservation
        highWatermarkBytes = max(highWatermarkBytes, currentBytes)
        if delta < 0 { resumptions = satisfyWaitersLocked() }
        lock.unlock()
        resume(resumptions)
        return true
    }

    fileprivate func transfer(
        id: UUID,
        to owner: EventPipelineMemoryOwner
    ) -> Bool {
        lock.lock()
        guard var reservation = reservations[id] else {
            lock.unlock()
            return false
        }
        if reservation.owner != owner {
            // R/P/H are stages of the same noncritical ownership class. Their
            // admission ceiling reserves J+S forward-progress space, but J/S
            // may legitimately occupy that space after the noncritical lease
            // was admitted. Relabelling H -> P (or another in-class handoff)
            // changes neither total nor noncritical bytes and must therefore
            // remain possible at the hard envelope; reapplying admission to
            // currentBytes here would strand an already-owned terminal result.
            //
            // A transfer across ownership classes still must obey the
            // destination ceiling. In particular, an S/J lease at the full
            // envelope cannot become noncritical ownership and erase reserved
            // codec/journal progress.
            if !sameAdmissionClass(reservation.owner, owner),
               (reservation.bytes > maximumIndividualRequestBytes(for: owner)
                    || currentBytes > maximumAggregateBytes(for: owner)) {
                increment(&nonblockingRejectionsTotal)
                increment(&nonblockingRejectionsTotalByOwner, owner: owner)
                lock.unlock()
                return false
            }
            bytesByOwner[reservation.owner, default: 0] -= reservation.bytes
            bytesByOwner[owner, default: 0] += reservation.bytes
            reservation.owner = owner
            reservations[id] = reservation
        }
        lock.unlock()
        return true
    }

    private func sameAdmissionClass(
        _ lhs: EventPipelineMemoryOwner,
        _ rhs: EventPipelineMemoryOwner
    ) -> Bool {
        switch (lhs, rhs) {
        case (.eventSource, .eventSource),
             (.eventSource, .deferredPatch),
             (.eventSource, .heavyResult),
             (.deferredPatch, .eventSource),
             (.deferredPatch, .deferredPatch),
             (.deferredPatch, .heavyResult),
             (.heavyResult, .eventSource),
             (.heavyResult, .deferredPatch),
             (.heavyResult, .heavyResult):
            return true
        default:
            return lhs == rhs
        }
    }

    fileprivate func split(
        id: UUID,
        bytes: Int,
        owner: EventPipelineMemoryOwner
    ) -> EventPipelineMemoryLease? {
        guard bytes > 0 else { return nil }
        lock.lock()
        guard var source = reservations[id], bytes <= source.bytes else {
            lock.unlock()
            return nil
        }
        // v1.21.6-rc.45: the reserve gate applies to RELABELING, not to a
        // same-owner divide.
        //
        // `split` moves `bytes` from `source.owner` to `owner`. When those
        // differ it is a relabel, and relabeling into an owner whose ceiling
        // global usage already exceeds would consume that owner's reserve —
        // the protection `growthHonorsForwardProgressReserve` pins, and it
        // stays. When they are the SAME owner, `bytesByOwner` is provably
        // unchanged for every owner (the decrement and increment below cancel),
        // `currentBytes` is unchanged, and no reserve can be consumed. Gating
        // that case is a check against growth an operation cannot cause.
        //
        // The sole production caller — HeavyEnrichmentPlane.terminalize, carving
        // a terminal marker out of a `.heavyResult` subscriber lease into
        // `.heavyResult` — is exactly the same-owner case, and it force-unwrapped
        // the result. Because `maximumAggregateBytes(.heavyResult)` is
        // `maximumBytes - forwardProgressReserveBytes` and the clause compared
        // GLOBAL `currentBytes` against it, every heavy-result split failed once
        // total pipeline usage crossed the forward-progress line — which is
        // precisely when operations time out and that path runs. Result: 16
        // identical SIGTRAPs on installed hosts between 2026-08-23 and
        // 2026-08-30, across rc.43 and rc.44.
        let relabels = owner != source.owner
        if bytes > maximumIndividualRequestBytes(for: owner)
            || (relabels && currentBytes > maximumAggregateBytes(for: owner)) {
            increment(&nonblockingRejectionsTotal)
            increment(&nonblockingRejectionsTotalByOwner, owner: owner)
            lock.unlock()
            return nil
        }
        source.bytes -= bytes
        reservations[id] = source
        bytesByOwner[source.owner, default: 0] -= bytes
        let splitID = UUID()
        reservations[splitID] = Reservation(owner: owner, bytes: bytes)
        increment(&acquisitionTotal)
        bytesByOwner[owner, default: 0] += bytes
        let lease = EventPipelineMemoryLease(id: splitID, budget: self)
        lock.unlock()
        return lease
    }

    fileprivate func release(id: UUID) {
        var resumptions: [(CheckedContinuation<EventPipelineMemoryLease?, Never>, EventPipelineMemoryLease?)] = []
        lock.lock()
        if let reservation = reservations.removeValue(forKey: id) {
            increment(&releaseTotal)
            currentBytes = max(0, currentBytes - reservation.bytes)
            bytesByOwner[reservation.owner, default: 0] = max(
                0,
                bytesByOwner[reservation.owner, default: 0] - reservation.bytes
            )
            resumptions = satisfyWaitersLocked()
        }
        lock.unlock()
        resume(resumptions)
    }

    /// The continuation closure calls this synchronous helper immediately
    /// after the cancellation handler is installed. The lock therefore never
    /// crosses an async suspension, and the fixed waiter limit covers every
    /// retained continuation owned by this budget.
    private func registerAcquire(
        id: UUID,
        bytes: Int,
        owner: EventPipelineMemoryOwner,
        taskIsCancelled: Bool,
        continuation: CheckedContinuation<EventPipelineMemoryLease?, Never>
    ) {
        var immediate: EventPipelineMemoryLease?
        var returnsNil = false
        lock.lock()
        if bytes <= 0
            || bytes > maximumIndividualRequestBytes(for: owner) {
            increment(&oversizedRequestsTotal)
            increment(&oversizedRequestsTotalByOwner, owner: owner)
            returnsNil = true
        } else if taskIsCancelled {
            increment(&cancelledWaiterTotal)
            returnsNil = true
        } else if canAcquireAheadOfWaitersLocked(owner: owner),
                  canAcquireLocked(bytes: bytes, owner: owner) {
            immediate = createReservationLocked(bytes: bytes, owner: owner)
        } else if waiters.count >= maximumWaiters {
            increment(&waiterLimitSaturationsTotal)
            increment(&waiterLimitSaturationsTotalByOwner, owner: owner)
            returnsNil = true
        } else {
            waiters.append(Waiter(
                id: id,
                bytes: bytes,
                owner: owner,
                continuation: continuation
            ))
            increment(&waitsTotal)
            increment(&waitsTotalByOwner, owner: owner)
            waiterHighWatermark = max(waiterHighWatermark, waiters.count)
            // Bounded by maximumWaiters (64 in production); cheap under lock.
            let ownerWaiterCount = waiters.reduce(0) {
                $0 + ($1.owner == owner ? 1 : 0)
            }
            waiterHighWatermarkByOwner[owner] = max(
                waiterHighWatermarkByOwner[owner, default: 0],
                ownerWaiterCount
            )
        }
        lock.unlock()
        if returnsNil {
            continuation.resume(returning: nil)
        } else if let immediate {
            continuation.resume(returning: immediate)
        }
    }

    private func recordAssignedWaiterCancellation() {
        lock.lock()
        increment(&cancelledWaiterTotal)
        lock.unlock()
    }

    private func cancelWaiter(id: UUID) {
        var continuation: CheckedContinuation<EventPipelineMemoryLease?, Never>?
        lock.lock()
        if let index = waiters.firstIndex(where: { $0.id == id }) {
            continuation = waiters.remove(at: index).continuation
            increment(&cancelledWaiterTotal)
        }
        let resumptions = satisfyWaitersLocked()
        lock.unlock()
        continuation?.resume(returning: nil)
        resume(resumptions)
    }

    private func createReservationLocked(
        bytes: Int,
        owner: EventPipelineMemoryOwner
    ) -> EventPipelineMemoryLease {
        let id = UUID()
        reservations[id] = Reservation(owner: owner, bytes: bytes)
        increment(&acquisitionTotal)
        currentBytes += bytes
        bytesByOwner[owner, default: 0] += bytes
        highWatermarkBytes = max(highWatermarkBytes, currentBytes)
        return EventPipelineMemoryLease(id: id, budget: self)
    }

    private func satisfyWaitersLocked() -> [(
        CheckedContinuation<EventPipelineMemoryLease?, Never>,
        EventPipelineMemoryLease?
    )] {
        var result: [(
            CheckedContinuation<EventPipelineMemoryLease?, Never>,
            EventPipelineMemoryLease?
        )] = []
        while true {
            // EventStore workspace is the downstream release valve for
            // already-retained J ownership, so it may bypass an older blocked
            // J waiter. FIFO remains strict within each owner class.
            let storageIndex = waiters.firstIndex {
                $0.owner == .eventStoreWorkspace
            }
            let journalIndex = waiters.firstIndex {
                $0.owner == .journalPrepared
            }
            let selectedIndex: Int?
            if let storageIndex {
                let storage = waiters[storageIndex]
                selectedIndex = canAcquireLocked(
                    bytes: storage.bytes,
                    owner: storage.owner
                ) ? storageIndex : nil
            } else if let journalIndex {
                let journal = waiters[journalIndex]
                selectedIndex = canAcquireLocked(
                    bytes: journal.bytes,
                    owner: journal.owner
                ) ? journalIndex : nil
            } else if let first = waiters.first,
                      canAcquireLocked(bytes: first.bytes, owner: first.owner) {
                selectedIndex = 0
            } else {
                selectedIndex = nil
            }
            guard let selectedIndex else { break }
            let waiter = waiters.remove(at: selectedIndex)
            let lease = createReservationLocked(
                bytes: waiter.bytes,
                owner: waiter.owner
            )
            result.append((waiter.continuation, lease))
        }
        return result
    }

    /// Each owner class has a distinct aggregate ceiling. Noncritical R/P/H
    /// ownership leaves the complete J+S reserve. J may consume that J portion
    /// but must leave the codec's S workspace. S is the downstream release
    /// valve and may use the full envelope.
    private func canAcquireLocked(
        bytes: Int,
        owner: EventPipelineMemoryOwner
    ) -> Bool {
        guard bytes <= maximumIndividualRequestBytes(for: owner) else {
            return false
        }
        let limit = maximumAggregateBytes(for: owner)
        return bytes <= limit - min(currentBytes, limit)
    }

    private func maximumIndividualRequestBytes(
        for owner: EventPipelineMemoryOwner
    ) -> Int {
        switch owner {
        case .eventStoreWorkspace:
            return eventStoreWorkspaceReserveBytes
        case .journalPrepared:
            return maximumBytes - eventStoreWorkspaceReserveBytes
        case .eventSource, .deferredPatch, .heavyResult:
            return maximumBytes - forwardProgressReserveBytes
        }
    }

    private func maximumAggregateBytes(
        for owner: EventPipelineMemoryOwner
    ) -> Int {
        switch owner {
        case .eventStoreWorkspace:
            return maximumBytes
        case .journalPrepared:
            // Unoccupied S bytes stay unavailable to J. Once EventStore owns
            // S, its decoder may acquire the corresponding J/result lease and
            // the pair may jointly drive the envelope to the hard maximum.
            let storageBytes = bytesByOwner[
                .eventStoreWorkspace,
                default: 0
            ]
            return min(
                maximumBytes,
                maximumBytes - eventStoreWorkspaceReserveBytes
                    + storageBytes
            )
        case .eventSource, .deferredPatch, .heavyResult:
            return maximumBytes - forwardProgressReserveBytes
        }
    }

    /// Owners on the DRAIN side of the pipeline — the ones whose completion
    /// releases credit back to the envelope. They may take a non-blocking
    /// reservation ahead of parked waiters, because making them queue behind
    /// tasks that are themselves waiting on the drain is a priority inversion
    /// with no exit. This applies to `tryAcquire` ONLY; the blocking `acquire`
    /// path keeps strict FIFO ordering for everyone.
    private func isDrainSideOwner(_ owner: EventPipelineMemoryOwner) -> Bool {
        switch owner {
        case .eventStoreWorkspace, .journalPrepared:
            return true
        case .eventSource, .deferredPatch, .heavyResult:
            return false
        }
    }

    private func canAcquireAheadOfWaitersLocked(
        owner: EventPipelineMemoryOwner
    ) -> Bool {
        switch owner {
        case .eventStoreWorkspace:
            return !waiters.contains { $0.owner == .eventStoreWorkspace }
        case .journalPrepared:
            return !waiters.contains {
                $0.owner == .eventStoreWorkspace
                    || $0.owner == .journalPrepared
            }
        case .eventSource, .deferredPatch, .heavyResult:
            return waiters.isEmpty
        }
    }

    private func resume(_ resumptions: [(
        CheckedContinuation<EventPipelineMemoryLease?, Never>,
        EventPipelineMemoryLease?
    )]) {
        for (continuation, lease) in resumptions {
            if lease != nil {
                lock.lock()
                let hook = waiterAssignedHookForTesting
                lock.unlock()
                hook?()
            }
            continuation.resume(returning: lease)
        }
    }

    private func increment(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    /// Per-owner counterpart of ``increment(_:)`` for the v1.22.0 item6
    /// telemetry dictionaries. Always called under `lock`, alongside the
    /// matching aggregate `increment`.
    private func increment(
        _ dict: inout [EventPipelineMemoryOwner: UInt64],
        owner: EventPipelineMemoryOwner
    ) {
        let current = dict[owner, default: 0]
        if current < UInt64.max { dict[owner] = current + 1 }
    }
}
