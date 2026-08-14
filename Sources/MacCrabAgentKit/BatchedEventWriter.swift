// BatchedEventWriter.swift
// MacCrabAgentKit
//
// v1.21.4 (F2 / A1): async batched writer for events.db.
//
// The event-loop consumer used to `await eventStore.insert(event:)` inline —
// one SQLite transaction per event. Under a flood (measured on-device: 120k+
// file writes) that serialized ~120k transactions behind the single consumer,
// so the consumer couldn't drain the merged stream fast enough and the
// AsyncStream buffer evicted the oldest events (the 400k `events_dropped`
// observed on the rc.1 sysext).
//
// This actor decouples the DB write from detection. The consumer crosses a
// bounded async admission boundary; a background drain flushes accumulated
// events through the existing batch transaction
// `EventStore.insert(events:lane:)` — hundreds of transactions per burst
// instead of hundreds of thousands, and off the consumer's critical path.
//
// Safety: nothing downstream in the loop reads the event back from events.db —
// detection runs on the in-memory enriched event, and alert evidence is
// snapshotted in memory by AlertSink — so deferring the write loses no
// detection fidelity. The only best-effort casualty is the ±60s
// surrounding-context window, which may miss the last < flush-interval of
// events under a flood. Production base admission acquires shared memory
// before allocation and, at the local cap, forces a below-threshold drain and
// waits for ownership rather than shedding an otherwise valid event. Explicit
// rejection/cancellation remains visible through the distinct `droppedCount`
// ledger rather than being conflated with merged-stream loss.

import Foundation
import MacCrabCore
import os.log

/// The single events.db capability the batched writer needs. A protocol (rather
/// than the concrete `EventStore`) so tests can inject a fake that throws
/// `EventStoreError.busy` on demand to exercise the #13 transient-retry path.
/// `EventStore` (an actor) satisfies the async requirement via its isolation.
protocol EventBatchInserting: Sendable {
    func insert(
        events: [Event],
        lane: EventPipelineLane
    ) async throws -> EventBatchInsertResult
}

extension EventStore: EventBatchInserting {}

/// Once-prepared production fast path. Legacy test inserters can continue to
/// satisfy `EventBatchInserting`; EventStore consumes canonical bytes directly
/// and never repeats sanitization/encoding on its actor.
protocol EventPreparedBatchInserting: Sendable {
    func insert(
        preparedEvents: [EventJournalIngressPreparation],
        lane: EventPipelineLane
    ) async throws -> EventBatchInsertResult
}

extension EventStore: EventPreparedBatchInserting {}

/// Append-only journal capabilities used after the immutable base batch.
/// Keeping these separate preserves lightweight inserter fakes in the existing
/// writer suite; production EventStore supplies the complete capability.
protocol EventJournalMutating: Sendable {
    func ensureJournaled(
        _ prepared: EventJournalIngressPreparation,
        lane: EventPipelineLane,
        reason: EventJournalEnsureReason
    ) async throws -> EventJournalEnsureOutcome

    func appendTerminalRevisions(
        preparedEvents: [EventJournalIngressPreparation],
        lane: EventPipelineLane
    ) async throws -> EventTerminalRevisionBatchResult

    func appendTerminalDeltas(
        preparedDeltas: [EventTerminalDeltaStoragePreparation],
        lane: EventPipelineLane,
        workspaceLease: EventPipelineMemoryLease
    ) async throws -> EventTerminalDeltaBatchResult

    func promoteProjection(
        eventID: UUID,
        reviewedMatches: [RuleMatch]
    ) async throws -> ProjectionPromotionOutcome

    func verifyJournaled(
        eventID: UUID,
        canonicalSHA256: Data
    ) async throws -> EventJournalVerification
}

extension EventStore: EventJournalMutating {}

enum TerminalRevisionEnqueueOutcome: Sendable, Equatable {
    case unchanged
    case queued
    case rejected
}

struct JournalBaseEnqueueOutcome: Sendable {
    let admission: EventJournalAdmission?
    let sourceRetainedByteEstimate: Int
    let poisoned: Bool
}

actor BatchedEventWriter {
    private struct BufferedEvent: Sendable {
        let generation: UInt64
        let handle: EventJournalPreparedHandle

        var event: Event { handle.preparation.event }
    }

    /// Exact receipt outcome retained independently from the contiguous writer
    /// terminal ledger. A terminal generation can be filtered, dropped, or
    /// failed; only `.verified` proves that UUID reached the immutable journal.
    private struct JournalAdmissionResolution: Sendable {
        let eventID: UUID
        let status: EventJournalContextStatus
    }

    private final class WeakPreparedHandle: @unchecked Sendable {
        weak var value: EventJournalPreparedHandle?

        init(_ value: EventJournalPreparedHandle) { self.value = value }
    }

    private struct RepairPayloadLease: Sendable {
        let eventID: UUID
        let expiresAt: ContinuousClock.Instant
        let handle: WeakPreparedHandle
    }

    private struct BufferedTerminalRevision: Sendable {
        let handle: EventJournalPreparedHandle
        let lane: EventPipelineLane
        let admission: EventJournalAdmission
        /// Present only when reviewed-alert fanout is synchronously waiting for
        /// this exact terminal digest to become durable or durably poisoned.
        let settlementID: UUID?

        var event: Event { handle.preparation.event }
    }

    private struct TerminalSettlementResolution: Sendable {
        let status: EventJournalContextStatus
        let storageMutationGeneration: UInt64
    }

    struct TelemetrySnapshot: Sendable, Equatable {
        /// Every hand-off from EventLoop, including rows rejected at the hard
        /// cap. Together with the terminal counters and the two gauges below,
        /// this is an exact per-lane conservation ledger:
        /// offered = persisted + filtered + dropped + buffered + in-flight.
        let offeredByLane: [String: Int]
        /// Rows permanently shed after the detection loop saw the event.
        let droppedCount: Int
        let droppedByLane: [String: Int]
        /// Cumulative retry attempts; a row can contribute more than once.
        let retriedCount: Int
        let retriedByLane: [String: Int]
        /// Rows reported committed at write time. This cumulative history is not
        /// decremented if a later corruption recovery quarantines that database.
        let persistedCount: Int
        let persistedByLane: [String: Int]
        /// Intentional EventInsertFilter decisions. These are terminal storage
        /// outcomes, not writer sheds and not detection-input losses.
        let filteredCount: Int
        let filteredByLane: [String: Int]
        let poisonedCount: Int
        let poisonedByLane: [String: Int]
        /// Rows waiting in the actor's queue at snapshot time. A batch currently
        /// suspended inside `store.insert` is not part of this queue gauge; it is
        /// reported separately by `inFlightDepth`.
        let bufferDepth: Int
        let bufferDepthByLane: [String: Int]
        let bufferRetainedBytes: Int
        let bufferRetainedBytesByLane: [String: Int]
        /// Rows detached from the queue and currently owned by one asynchronous
        /// `store.insert` call. This closes the heartbeat reconciliation gap where
        /// the queue could read zero before the corresponding persisted/drop
        /// counters advanced.
        let inFlightDepth: Int
        let inFlightDepthByLane: [String: Int]
        let inFlightRetainedBytes: Int
        let inFlightRetainedBytesByLane: [String: Int]
        /// Append-only terminal-overlay conservation. Retry attempts are
        /// intentionally separate because one offered revision may retry more
        /// than once. Any dropped terminal revision is canonical-evidence
        /// poison even when the immutable-base ledger remains green.
        let terminalRevisionOfferedCount: Int
        let terminalRevisionOfferedByLane: [String: Int]
        let terminalRevisionUnchangedCount: Int
        let terminalRevisionUnchangedByLane: [String: Int]
        let terminalRevisionDurableCount: Int
        let terminalRevisionDurableByLane: [String: Int]
        let terminalRevisionDroppedCount: Int
        let terminalRevisionDroppedByLane: [String: Int]
        /// Subset of dropped terminal work that durably wrote a content-bound
        /// poison ledger row instead of an exact terminal revision.
        let terminalRevisionPoisonedCount: Int
        let terminalRevisionPoisonedByLane: [String: Int]
        let terminalRevisionRetriedCount: Int
        let terminalRevisionRetriedByLane: [String: Int]
        let terminalRevisionBufferDepth: Int
        let terminalRevisionBufferDepthByLane: [String: Int]
        let terminalRevisionBufferRetainedBytes: Int
        let terminalRevisionBufferRetainedBytesByLane: [String: Int]
        let terminalRevisionInFlightDepth: Int
        let terminalRevisionInFlightDepthByLane: [String: Int]
        let terminalRevisionInFlightRetainedBytes: Int
        let terminalRevisionInFlightRetainedBytesByLane: [String: Int]
        /// Global handle ownership includes queue/in-flight work plus prepared
        /// values inherited by EventLoop/TaskLocal/deferred children.
        let preparedOwnershipCount: Int
        let preparedOwnershipCompactReceiptCount: Int
        let preparedOwnershipLiveHandleCount: Int
        let preparedOwnershipBytes: Int
        let preparedOwnershipMaximumCount: Int
        let preparedOwnershipMaximumBytes: Int
        let terminalStorageMutationGeneration: UInt64
        /// Highest event accepted into the bounded writer and highest
        /// contiguous generation that reached a terminal persistence outcome.
        /// Evidence capture waits on this ledger instead of racing the 250 ms
        /// batch window.
        let admittedGeneration: UInt64
        let terminalGeneration: UInt64
        /// Bounded receipt-era gaps that can still be repaired by an exact
        /// security-relevant admission, plus the oldest aged-out permanent gap.
        let repairableJournalGapCount: Int
        let earliestJournalGapGeneration: UInt64?
        let repairPayloadLeaseCount: Int
        let repairPayloadExpiredTotal: UInt64

        var terminalRevisionAccountedCount: Int {
            terminalRevisionUnchangedCount
                + terminalRevisionDurableCount
                + terminalRevisionDroppedCount
                + terminalRevisionPoisonedCount
                + terminalRevisionBufferDepth
                + terminalRevisionInFlightDepth
        }

        var terminalRevisionConservationHolds: Bool {
            terminalRevisionOfferedCount == terminalRevisionAccountedCount
        }

        var terminalRevisionEvidencePoisoned: Bool {
            terminalRevisionDroppedCount > 0
                || terminalRevisionPoisonedCount > 0
                || !terminalRevisionConservationHolds
        }
    }

    private let store: any EventBatchInserting
    private let journalStore: (any EventJournalMutating)?
    /// Kick a background drain once the buffer reaches this depth.
    private let flushThreshold: Int
    /// Hard ceiling on retained prepared handles. Production async admission
    /// forces a drain and backpressures at this boundary; the synchronous
    /// compatibility seam may reject rather than exceed it.
    private let hardCap: Int
    /// Shared base + terminal + lifecycle prepared-handle byte ceiling.
    private let hardByteCap: Int
    private let ownershipBudget: EventJournalPreparedOwnershipBudget
    private let liveMemoryBudget: EventPipelineLiveMemoryBudget
    private var terminalDeltaStorageLeaseGrowthHookForTesting:
        (@Sendable () async -> Void)?
    /// Volume to probe for free space before writing, or nil to disable the
    /// admission check (tests, and any consumer with no on-disk store).
    private let volumePath: String?
    /// Free-space reserve the writer refuses to consume. The engine previously
    /// had NO free-space check on any write path — `statvfs` appeared only in
    /// VACUUM preflights — so the root daemon would write until the volume was
    /// 100% full, taking the whole machine with it. Disk-full was handled only
    /// reactively, in `drain`'s permanent-error arm, i.e. after the damage.
    private let freeSpaceFloorMB: Int
    /// Cached admission probe. `statvfs` is a syscall and `drain` loops per
    /// batch, so re-probe at most every 15s.
    private var lastFreeProbe: (at: ContinuousClock.Instant, freeMB: Int)?
    /// True once the floor has been breached, so the fault logs once per episode
    /// instead of once per batch.
    private var admissionBlocked = false

    /// Separate queues make the storage policy explicit: priority rows are
    /// always detached before file-firehose rows, and every database batch is
    /// lane-homogeneous. The latter is what makes EventStore's aggregate
    /// persisted/filtered result attributable without guessing.
    private var buffers = [[BufferedEvent]](
        repeating: [], count: EventPipelineLane.allCases.count
    )
    private var bufferedBytesByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    /// Final synchronous/deferred overlays are append-only and batched on the
    /// same writer task. They never overwrite the immutable base block.
    private var terminalRevisionBuffers = [[BufferedTerminalRevision]](
        repeating: [], count: EventPipelineLane.allCases.count
    )
    private var terminalRevisionBufferedBytesByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    /// Exactly one drain runs at a time, so this is either zero or the complete
    /// detached batch suspended in `store.insert(events:lane:)`.
    private var inFlightDepth = 0
    private var inFlightDepthByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var inFlightBytes = 0
    private var inFlightBytesByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var terminalRevisionInFlightDepth = 0
    private var terminalRevisionInFlightDepthByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var terminalRevisionInFlightBytes = 0
    private var terminalRevisionInFlightBytesByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    /// Sparse terminal calls settle directly against EventStore rather than
    /// entering the legacy full-Event queue. Actor reentrancy allows several
    /// calls to be suspended concurrently, so account them additively.
    private var sparseTerminalInFlightDepth = 0
    private var sparseTerminalInFlightDepthByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var sparseTerminalInFlightBytes = 0
    private var sparseTerminalInFlightBytesByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var terminalStorageMutationGeneration: UInt64 = 0
    /// Bounded by accepted terminal-buffer ownership. Timed-out callers remove
    /// their id immediately; late storage completion therefore cannot grow an
    /// abandoned receipt history.
    private var activeTerminalSettlementIDs: Set<UUID> = []
    private var terminalSettlementResolutions:
        [UUID: TerminalSettlementResolution] = [:]
    private var admittedGeneration: UInt64 = 0
    private var terminalGeneration: UInt64 = 0
    /// Accepted generations without a terminal persistence outcome. This set
    /// is bounded by the writer hard cap plus its one detached batch; unlike an
    /// out-of-order terminal history, it cannot grow forever if a file-lane row
    /// remains behind sustained priority traffic.
    private var pendingGenerations: Set<UInt64> = []
    /// Identity exists from queue admission until its bounded terminal history
    /// entry ages out. Pending entries cannot age out.
    private var eventIDByGeneration: [UInt64: UUID] = [:]
    private var canonicalSHA256ByGeneration: [UInt64: Data] = [:]
    private var canonicalByteCountByGeneration: [UInt64: Int] = [:]
    private var admissionResolutions: [UInt64: JournalAdmissionResolution] = [:]
    private var resolutionOrder: [UInt64] = []
    private var resolutionOrderHead = 0
    /// Enough history for delayed child work while keeping receipt ownership
    /// independent from unbounded daemon uptime.
    private let admissionResolutionCapacity: Int
    /// Repairable gaps are retained only while their identity receipt remains
    /// in the bounded history. Once such a receipt ages out, a single earliest
    /// permanent generation is sufficient: every later prefix is incomplete
    /// and that old identity can no longer be safely repaired. This prevents a
    /// disk-failure episode from growing one Set entry per event forever.
    private var earliestPermanentJournalGapGeneration: UInt64?
    private var repairableJournalGapGenerations: Set<UInt64> = []
    /// Only non-durable candidates whose receipts still own their exact
    /// prepared payload appear here. Entries are weak, bounded by the shared
    /// byte envelope, and swept by the 250 ms writer cadence. After the lease
    /// expires the receipt is compact but explicitly non-verifiable.
    private var repairPayloadLeases: [UInt64: RepairPayloadLease] = [:]
    private let repairPayloadLeaseDuration: Duration
    private let repairClock = ContinuousClock()
    private var repairPayloadExpiredTotal: UInt64 = 0

    private var earliestJournalGapGeneration: UInt64? {
        switch (
            earliestPermanentJournalGapGeneration,
            repairableJournalGapGenerations.min()
        ) {
        case (nil, nil): return nil
        case (let permanent?, nil): return permanent
        case (nil, let repairable?): return repairable
        case (let permanent?, let repairable?):
            return min(permanent, repairable)
        }
    }

    private var draining = false
    /// Joinable handle for both threshold-triggered and timer-triggered drains.
    /// Shutdown must not infer completion from `draining`: the actor can be
    /// suspended inside SQLite while that flag is true.
    private var drainTask: Task<Void, Never>?
    private var flushLoop: Task<Void, Never>?
    /// Storage-write drops since start (writer-queue overflow). A `LockedCounter`
    /// (Sendable, lock-guarded) so `droppedCount` can be read `nonisolated` from
    /// the heartbeat without an actor hop.
    private let drops = LockedCounter()
    /// Events re-queued after a TRANSIENT (SQLITE_BUSY/LOCKED) batch failure —
    /// retried rather than dropped (#13). Distinct from `drops` so a deferred
    /// retry is never conflated with a lost row.
    private let retries = LockedCounter()
    /// Rows confirmed durable by successful commits. Partial batch failures add
    /// only their committed prefix; filtered rows are neither persisted nor
    /// misreported as storage sheds.
    private let persisted = LockedCounter()
    private let terminalRevisionDrops = LockedCounter()
    private let terminalRevisionDurable = LockedCounter()
    private let terminalRevisionOffered = LockedCounter()
    private let terminalRevisionUnchanged = LockedCounter()
    private let terminalRevisionRetries = LockedCounter()
    private let terminalRevisionPoisoned = LockedCounter()
    /// Actor-isolated lane ledgers. Totals above remain lock-backed for the
    /// existing nonisolated compatibility accessors.
    private var offeredByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var droppedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var retriedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var persistedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var filteredByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var poisonedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var terminalRevisionOfferedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var terminalRevisionUnchangedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var terminalRevisionDurableByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var terminalRevisionDroppedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var terminalRevisionRetriedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )
    private var terminalRevisionPoisonedByLane = [Int](
        repeating: 0, count: EventPipelineLane.allCases.count
    )

    /// Storage-write drops since start. NOT a detection gap — the event was
    /// fully processed by the pipeline; only its events.db row was dropped.
    nonisolated var droppedCount: Int { drops.get() }

    /// Cumulative events re-queued after transient contention (#13 observability).
    nonisolated var retriedCount: Int { retries.get() }

    nonisolated var persistedCount: Int { persisted.get() }
    nonisolated var terminalRevisionDroppedCount: Int {
        terminalRevisionDrops.get()
    }
    nonisolated var terminalRevisionDurableCount: Int {
        terminalRevisionDurable.get()
    }

    /// One actor-consistent view for the rich heartbeat. Counter values are
    /// cumulative since process start; buffer depth is an instantaneous gauge.
    func telemetrySnapshot() -> TelemetrySnapshot {
        sweepRepairPayloadLeases()
        let ownership = ownershipBudget.snapshot()
        return TelemetrySnapshot(
            offeredByLane: laneDictionary(offeredByLane),
            droppedCount: drops.get(),
            droppedByLane: laneDictionary(droppedByLane),
            retriedCount: retries.get(),
            retriedByLane: laneDictionary(retriedByLane),
            persistedCount: persisted.get(),
            persistedByLane: laneDictionary(persistedByLane),
            filteredCount: filteredByLane.reduce(0, +),
            filteredByLane: laneDictionary(filteredByLane),
            poisonedCount: poisonedByLane.reduce(0, +),
            poisonedByLane: laneDictionary(poisonedByLane),
            bufferDepth: bufferDepth,
            bufferDepthByLane: laneDictionary(buffers.map(\.count)),
            bufferRetainedBytes: bufferedBytesByLane.reduce(0, +),
            bufferRetainedBytesByLane: laneDictionary(bufferedBytesByLane),
            inFlightDepth: inFlightDepth,
            inFlightDepthByLane: laneDictionary(inFlightDepthByLane),
            inFlightRetainedBytes: inFlightBytes,
            inFlightRetainedBytesByLane: laneDictionary(inFlightBytesByLane),
            terminalRevisionOfferedCount: terminalRevisionOffered.get(),
            terminalRevisionOfferedByLane:
                laneDictionary(terminalRevisionOfferedByLane),
            terminalRevisionUnchangedCount: terminalRevisionUnchanged.get(),
            terminalRevisionUnchangedByLane:
                laneDictionary(terminalRevisionUnchangedByLane),
            terminalRevisionDurableCount: terminalRevisionDurable.get(),
            terminalRevisionDurableByLane:
                laneDictionary(terminalRevisionDurableByLane),
            terminalRevisionDroppedCount: terminalRevisionDrops.get(),
            terminalRevisionDroppedByLane:
                laneDictionary(terminalRevisionDroppedByLane),
            terminalRevisionPoisonedCount: terminalRevisionPoisoned.get(),
            terminalRevisionPoisonedByLane:
                laneDictionary(terminalRevisionPoisonedByLane),
            terminalRevisionRetriedCount: terminalRevisionRetries.get(),
            terminalRevisionRetriedByLane:
                laneDictionary(terminalRevisionRetriedByLane),
            terminalRevisionBufferDepth: terminalRevisionDepth,
            terminalRevisionBufferDepthByLane:
                laneDictionary(terminalRevisionBuffers.map(\.count)),
            terminalRevisionBufferRetainedBytes:
                terminalRevisionBufferedBytesByLane.reduce(0, +),
            terminalRevisionBufferRetainedBytesByLane:
                laneDictionary(terminalRevisionBufferedBytesByLane),
            terminalRevisionInFlightDepth:
                terminalRevisionInFlightDepth + sparseTerminalInFlightDepth,
            terminalRevisionInFlightDepthByLane:
                laneDictionary(zip(
                    terminalRevisionInFlightDepthByLane,
                    sparseTerminalInFlightDepthByLane
                ).map { $0.0 + $0.1 }),
            terminalRevisionInFlightRetainedBytes:
                terminalRevisionInFlightBytes + sparseTerminalInFlightBytes,
            terminalRevisionInFlightRetainedBytesByLane:
                laneDictionary(zip(
                    terminalRevisionInFlightBytesByLane,
                    sparseTerminalInFlightBytesByLane
                ).map { $0.0 + $0.1 }),
            preparedOwnershipCount: ownership.retainedCount,
            preparedOwnershipCompactReceiptCount:
                ownership.compactReceiptCount,
            preparedOwnershipLiveHandleCount: ownership.liveHandleCount,
            preparedOwnershipBytes: ownership.retainedBytes,
            preparedOwnershipMaximumCount: ownership.maximumCount,
            preparedOwnershipMaximumBytes: ownership.maximumBytes,
            terminalStorageMutationGeneration:
                terminalStorageMutationGeneration,
            admittedGeneration: admittedGeneration,
            terminalGeneration: terminalGeneration,
            repairableJournalGapCount:
                repairableJournalGapGenerations.count,
            earliestJournalGapGeneration: earliestJournalGapGeneration,
            repairPayloadLeaseCount: repairPayloadLeases.count,
            repairPayloadExpiredTotal: repairPayloadExpiredTotal
        )
    }

    private var bufferDepth: Int {
        buffers.reduce(0) { $0 + $1.count }
    }

    private var terminalRevisionDepth: Int {
        terminalRevisionBuffers.reduce(0) { $0 + $1.count }
    }

    private var hasPendingStorageWork: Bool {
        bufferDepth > 0 || terminalRevisionDepth > 0
    }

    private func laneDictionary(_ values: [Int]) -> [String: Int] {
        var result: [String: Int] = [:]
        for lane in EventPipelineLane.allCases {
            result[lane.key] = values[lane.rawValue]
        }
        return result
    }

    private func recordDrop(_ count: Int, lane: EventPipelineLane) {
        guard count > 0 else { return }
        drops.add(count)
        droppedByLane[lane.rawValue] += count
    }

    private func recordRetry(_ count: Int, lane: EventPipelineLane) {
        guard count > 0 else { return }
        retries.add(count)
        retriedByLane[lane.rawValue] += count
    }

    private func recordPersisted(_ count: Int, lane: EventPipelineLane) {
        guard count > 0 else { return }
        persisted.add(count)
        persistedByLane[lane.rawValue] += count
    }

    private func recordFiltered(_ count: Int, lane: EventPipelineLane) {
        guard count > 0 else { return }
        filteredByLane[lane.rawValue] += count
    }

    private func recordPoisoned(_ count: Int, lane: EventPipelineLane) {
        guard count > 0 else { return }
        poisonedByLane[lane.rawValue] += count
    }

    private func poisonedCount(in result: EventBatchInsertResult) -> Int {
        result.inputDispositions.reduce(into: 0) { count, disposition in
            if case .poisoned = disposition { count += 1 }
        }
    }

    private func evictNewestQueuedFileForPriorityAdmission() {
        let index = EventPipelineLane.file.rawValue
        guard let evicted = buffers[index].popLast() else { return }
        bufferedBytesByLane[index] = max(
            0,
            bufferedBytesByLane[index]
                - evicted.handle.retainedByteCharge
        )
        recordDrop(1, lane: .file)
        markTerminal(CollectionOfOne(evicted))
    }

    private func setInFlight(
        _ events: [BufferedEvent],
        lane: EventPipelineLane
    ) {
        let bytes = events.reduce(0) {
            $0 + $1.handle.retainedByteCharge
        }
        inFlightDepth = events.count
        inFlightDepthByLane[lane.rawValue] = events.count
        inFlightBytes = bytes
        inFlightBytesByLane[lane.rawValue] = bytes
    }

    private func clearInFlight(lane: EventPipelineLane) {
        inFlightDepth = 0
        inFlightDepthByLane[lane.rawValue] = 0
        inFlightBytes = 0
        inFlightBytesByLane[lane.rawValue] = 0
    }

    private func recordTerminalOffered(lane: EventPipelineLane) {
        terminalRevisionOffered.increment()
        terminalRevisionOfferedByLane[lane.rawValue] += 1
    }

    private func recordTerminalUnchanged(
        _ count: Int = 1,
        lane: EventPipelineLane
    ) {
        guard count > 0 else { return }
        terminalRevisionUnchanged.add(count)
        terminalRevisionUnchangedByLane[lane.rawValue] += count
    }

    private func recordTerminalDurable(
        _ count: Int = 1,
        lane: EventPipelineLane
    ) {
        guard count > 0 else { return }
        terminalRevisionDurable.add(count)
        terminalRevisionDurableByLane[lane.rawValue] += count
    }

    private func recordTerminalDrop(
        _ count: Int = 1,
        lane: EventPipelineLane
    ) {
        guard count > 0 else { return }
        terminalRevisionDrops.add(count)
        terminalRevisionDroppedByLane[lane.rawValue] += count
    }

    private func resolveTerminalSettlement(
        _ item: BufferedTerminalRevision,
        status: EventJournalContextStatus,
        storageMutationGeneration: UInt64 = 0
    ) {
        guard let settlementID = item.settlementID,
              activeTerminalSettlementIDs.contains(settlementID) else {
            return
        }
        terminalSettlementResolutions[settlementID]
            = TerminalSettlementResolution(
                status: status,
                storageMutationGeneration: storageMutationGeneration
            )
    }

    private func recordTerminalDrop(
        _ items: [BufferedTerminalRevision],
        status: EventJournalContextStatus = .failed
    ) {
        guard !items.isEmpty else { return }
        let byLane = Dictionary(grouping: items, by: \.lane)
        for (lane, laneItems) in byLane {
            recordTerminalDrop(laneItems.count, lane: lane)
        }
        for item in items {
            resolveTerminalSettlement(item, status: status)
        }
    }

    private func recordTerminalRetry(
        _ count: Int,
        lane: EventPipelineLane
    ) {
        guard count > 0 else { return }
        terminalRevisionRetries.add(count)
        terminalRevisionRetriedByLane[lane.rawValue] += count
    }

    private func recordTerminalPoisoned(lane: EventPipelineLane) {
        terminalRevisionPoisoned.increment()
        terminalRevisionPoisonedByLane[lane.rawValue] += 1
    }

    private func setTerminalRevisionInFlight(
        _ items: [BufferedTerminalRevision],
        lane: EventPipelineLane
    ) {
        let bytes = items.reduce(0) {
            $0 + $1.handle.retainedByteCharge
        }
        terminalRevisionInFlightDepth = items.count
        terminalRevisionInFlightDepthByLane[lane.rawValue] = items.count
        terminalRevisionInFlightBytes = bytes
        terminalRevisionInFlightBytesByLane[lane.rawValue] = bytes
    }

    private func clearTerminalRevisionInFlight(lane: EventPipelineLane) {
        terminalRevisionInFlightDepth = 0
        terminalRevisionInFlightDepthByLane[lane.rawValue] = 0
        terminalRevisionInFlightBytes = 0
        terminalRevisionInFlightBytesByLane[lane.rawValue] = 0
    }

    private func beginSparseTerminalInFlight(
        lane: EventPipelineLane,
        bytes: Int
    ) {
        sparseTerminalInFlightDepth += 1
        sparseTerminalInFlightDepthByLane[lane.rawValue] += 1
        sparseTerminalInFlightBytes += bytes
        sparseTerminalInFlightBytesByLane[lane.rawValue] += bytes
    }

    private func endSparseTerminalInFlight(
        lane: EventPipelineLane,
        bytes: Int
    ) {
        sparseTerminalInFlightDepth = max(0, sparseTerminalInFlightDepth - 1)
        sparseTerminalInFlightDepthByLane[lane.rawValue] = max(
            0,
            sparseTerminalInFlightDepthByLane[lane.rawValue] - 1
        )
        sparseTerminalInFlightBytes = max(
            0,
            sparseTerminalInFlightBytes - bytes
        )
        sparseTerminalInFlightBytesByLane[lane.rawValue] = max(
            0,
            sparseTerminalInFlightBytesByLane[lane.rawValue] - bytes
        )
    }

    private func markTerminal(
        _ events: some Collection<BufferedEvent>,
        status: EventJournalContextStatus = .dropped
    ) {
        for item in events {
            recordAdmissionResolution(item, status: status)
            pendingGenerations.remove(item.generation)
        }
        if let oldestPending = pendingGenerations.min() {
            terminalGeneration = oldestPending > 0 ? oldestPending - 1 : 0
        } else {
            terminalGeneration = admittedGeneration
        }
    }

    private func markTerminal(
        _ events: some Collection<BufferedEvent>,
        result: EventBatchInsertResult,
        allowUncommitted: Bool = false
    ) {
        let batch = Array(events)
        guard result.inputDispositions.count == batch.count else {
            // Old/test inserters may omit the ordered ledger. Counts cannot map
            // duplicate UUID/value multiplicity, so unknown is a real gap.
            markTerminal(batch, status: .failed)
            return
        }
        for (item, disposition) in zip(batch, result.inputDispositions) {
            let status: EventJournalContextStatus?
            switch disposition {
            case .durable(let eventID):
                status = eventID == item.event.id ? .verified : .failed
            case .poisoned(let evidence):
                status = evidence.originalEventID == item.event.id
                    ? .poisoned : .failed
            case .filtered(let eventID):
                status = eventID == item.event.id ? .filtered : .failed
            case .uncommitted(let eventID):
                // Partial failure retains this exact envelope for retry. A bad
                // identity is terminal poison; a valid identity stays pending.
                status = allowUncommitted && eventID == item.event.id
                    ? nil : .failed
            }
            if let status {
                recordAdmissionResolution(item, status: status)
                pendingGenerations.remove(item.generation)
            }
        }
        if let oldestPending = pendingGenerations.min() {
            terminalGeneration = oldestPending > 0 ? oldestPending - 1 : 0
        } else {
            terminalGeneration = admittedGeneration
        }
    }

    private func recordAdmissionResolution(
        _ item: BufferedEvent,
        status: EventJournalContextStatus
    ) {
        admissionResolutions[item.generation] = JournalAdmissionResolution(
            eventID: item.event.id,
            status: status
        )
        resolutionOrder.append(item.generation)
        switch status {
        case .verified:
            repairPayloadLeases.removeValue(forKey: item.generation)
            item.handle.compactAfterDurableVerification()
        case .poisoned:
            // EventStore durably owns the content-bound poison record. It can
            // never be repaired into exact evidence and is a permanent prefix
            // gap, so retaining the marker Event/JSON serves no purpose.
            item.handle.compactAfterDurableVerification()
            makeJournalGapPermanent(generation: item.generation)
        case .filtered:
            registerRepairPayloadLease(for: item)
        case .dropped, .failed, .unavailable:
            repairableJournalGapGenerations.insert(item.generation)
            registerRepairPayloadLease(for: item)
        case .repairExpired:
            item.handle.compactAfterRepairExpiry()
            makeJournalGapPermanent(generation: item.generation)
        case .timedOut, .mismatchedReceipt, .prefixIncomplete:
            // These are verifier results rather than storage resolutions. If a
            // future caller feeds one here, fail closed as repairable evidence
            // loss while the exact prepared value remains leased.
            repairableJournalGapGenerations.insert(item.generation)
            registerRepairPayloadLease(for: item)
        }
        trimAdmissionResolutionHistory()
    }

    private func registerRepairPayloadLease(for item: BufferedEvent) {
        guard item.handle.availablePreparation != nil else { return }
        repairPayloadLeases[item.generation] = RepairPayloadLease(
            eventID: item.event.id,
            expiresAt: repairClock.now.advanced(
                by: repairPayloadLeaseDuration
            ),
            handle: WeakPreparedHandle(item.handle)
        )
    }

    private func makeJournalGapPermanent(generation: UInt64) {
        repairableJournalGapGenerations.remove(generation)
        if let prior = earliestPermanentJournalGapGeneration {
            earliestPermanentJournalGapGeneration = min(prior, generation)
        } else {
            earliestPermanentJournalGapGeneration = generation
        }
    }

    /// Compact abandoned/expired repair payloads without retaining receipts in
    /// the writer. A failed generation stays repairable past resolution-history
    /// aging only while an internal receipt still owns the exact value.
    private func sweepRepairPayloadLeases() {
        let now = repairClock.now
        for generation in Array(repairPayloadLeases.keys) {
            guard let lease = repairPayloadLeases[generation] else { continue }
            guard let handle = lease.handle.value else {
                repairPayloadLeases.removeValue(forKey: generation)
                if repairableJournalGapGenerations.contains(generation) {
                    makeJournalGapPermanent(generation: generation)
                }
                continue
            }
            guard now >= lease.expiresAt else { continue }
            repairPayloadLeases.removeValue(forKey: generation)
            if handle.compactAfterRepairExpiry(),
               repairPayloadExpiredTotal < UInt64.max {
                repairPayloadExpiredTotal += 1
            }
            if admissionResolutions[generation]?.eventID == lease.eventID {
                admissionResolutions[generation]
                    = JournalAdmissionResolution(
                        eventID: lease.eventID,
                        status: .repairExpired
                    )
            }
            if repairableJournalGapGenerations.contains(generation) {
                makeJournalGapPermanent(generation: generation)
            }
        }
    }

    private func trimAdmissionResolutionHistory() {
        while resolutionOrder.count - resolutionOrderHead
                > admissionResolutionCapacity {
            let generation = resolutionOrder[resolutionOrderHead]
            resolutionOrderHead += 1
            // A generation is appended exactly once when it becomes terminal.
            admissionResolutions.removeValue(forKey: generation)
            eventIDByGeneration.removeValue(forKey: generation)
            canonicalSHA256ByGeneration.removeValue(forKey: generation)
            canonicalByteCountByGeneration.removeValue(forKey: generation)
            if repairableJournalGapGenerations.contains(generation) {
                // History capacity is not a repair deadline. A delayed child
                // with the internal handle may still repair through EventStore;
                // only absent/expired payload ownership makes the gap permanent.
                if repairPayloadLeases[generation]?.handle.value == nil {
                    repairPayloadLeases.removeValue(forKey: generation)
                    makeJournalGapPermanent(generation: generation)
                }
            }
        }
        if resolutionOrderHead >= 4_096,
           resolutionOrderHead * 2 >= resolutionOrder.count {
            resolutionOrder.removeFirst(resolutionOrderHead)
            resolutionOrderHead = 0
        }
    }

    /// Priority first. A batch is deliberately one lane only so the store's
    /// aggregate result remains exactly attributable.
    private func detachNextBatch() -> (
        lane: EventPipelineLane,
        events: [BufferedEvent]
    )? {
        for lane in [EventPipelineLane.priority, .file]
        where !buffers[lane.rawValue].isEmpty {
            let batch = buffers[lane.rawValue]
            buffers[lane.rawValue].removeAll(keepingCapacity: true)
            bufferedBytesByLane[lane.rawValue] = 0
            return (lane, batch)
        }
        return nil
    }

    private func prependForRetry(
        _ events: [BufferedEvent],
        lane: EventPipelineLane
    ) -> Bool {
        guard !events.isEmpty else { return true }
        // Detached work retains its already-acquired handle reservation while
        // SQLite is suspended, so moving it back to the queue cannot exceed the
        // shared count/byte budget and never needs to evict newer ownership.
        buffers[lane.rawValue].insert(contentsOf: events, at: 0)
        bufferedBytesByLane[lane.rawValue] += events.reduce(0) {
            $0 + $1.handle.retainedByteCharge
        }
        recordRetry(events.count, lane: lane)
        return true
    }

    /// Reattach EventStore's exact ordered per-input outcomes to generation-
    /// bearing envelopes. Never hash/compare complete Event graphs here: one
    /// legal input may approach the journal ceiling and duplicate UUIDs remain
    /// distinguishable only by input ordinal.
    private func partitionPartialFailure(
        _ batch: [BufferedEvent],
        progress: EventBatchInsertResult,
        uncommittedEvents: [Event]
    ) -> (terminal: [BufferedEvent], uncommitted: [BufferedEvent])? {
        guard progress.inputDispositions.count == batch.count else {
            return nil
        }
        var terminal: [BufferedEvent] = []
        var uncommitted: [BufferedEvent] = []
        terminal.reserveCapacity(batch.count)
        uncommitted.reserveCapacity(uncommittedEvents.count)
        for (item, disposition) in zip(batch, progress.inputDispositions) {
            switch disposition {
            case .durable(let eventID), .filtered(let eventID):
                guard eventID == item.event.id else { return nil }
                terminal.append(item)
            case .poisoned(let evidence):
                guard evidence.originalEventID == item.event.id else {
                    return nil
                }
                terminal.append(item)
            case .uncommitted(let eventID):
                guard eventID == item.event.id else { return nil }
                uncommitted.append(item)
            }
        }
        guard uncommitted.map(\.event.id) == uncommittedEvents.map(\.id) else {
            return nil
        }
        return (terminal: terminal, uncommitted: uncommitted)
    }

    /// - Note: In production `flushThreshold` / `hardCap` are FIXED at their
    ///   defaults — the sole caller (`DaemonState.init`) constructs this writer
    ///   with no arguments, and there is deliberately NO `daemon_config.json`
    ///   surface for them (unlike the upstream priority/file stream caps, which
    ///   ARE config-tunable via `DaemonConfig.storage`). The parameters exist
    ///   only so tests can inject small values to exercise flush, bounded
    ///   backpressure, and compatibility-rejection branches. Should a config
    ///   surface ever be added, the caller —
    ///   not this initializer — must keep `flushThreshold <= hardCap`: we apply
    ///   floors only and do NOT silently clamp one to the other. The defaults
    ///   already satisfy 1000 <= 20_000. The former 250K default could itself retain
    ///   hundreds of MiB of Event object graphs, defeating the product RSS
    ///   budget before it ever became a useful backpressure boundary.
    init(
        store: any EventBatchInserting,
        flushThreshold: Int = 1000,
        hardCap: Int = EventJournalPreparedOwnershipBudget
            .productionMaximumLiveHandles,
        hardByteCap: Int = EventPipelineLiveMemoryBudget
            .productionMaximumBytes,
        admissionResolutionCapacity: Int = 65_536,
        repairPayloadLeaseDuration: Duration = .seconds(15 * 60),
        liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared,
        volumePath: String? = nil,
        freeSpaceFloorMB: Int = 1024
    ) {
        self.volumePath = volumePath
        self.freeSpaceFloorMB = max(0, freeSpaceFloorMB)
        self.store = store
        self.journalStore = store as? any EventJournalMutating
        self.flushThreshold = max(1, flushThreshold)
        self.hardCap = max(1, hardCap)
        self.hardByteCap = max(1, hardByteCap)
        self.liveMemoryBudget = liveMemoryBudget
        self.ownershipBudget = EventJournalPreparedOwnershipBudget(
            maximumCount: max(1, hardCap),
            maximumBytes: max(1, hardByteCap),
            liveMemoryBudget: liveMemoryBudget
        )
        self.admissionResolutionCapacity = max(
            1,
            admissionResolutionCapacity
        )
        // Fifteen minutes exceeds every configured alert barrier, heavy
        // operation, deferred replay, and shutdown completion window. Tests
        // inject a shorter duration to exercise expiry deterministically.
        self.repairPayloadLeaseDuration = max(
            .milliseconds(1),
            repairPayloadLeaseDuration
        )
    }

    internal func setTerminalDeltaStorageLeaseGrowthHookForTesting(
        _ hook: (@Sendable () async -> Void)?
    ) {
        terminalDeltaStorageLeaseGrowthHookForTesting = hook
    }

    /// Lossless bounded hand-off from the hot consumer. The explicit pipeline
    /// lane is preserved through storage rather than re-inferred from a broader
    /// "file category = cheap" rule (credential OPEN is a file-category event
    /// that deliberately rides the priority lane). At the shared hard cap the
    /// async path forces a drain and waits for ownership; it never raises the
    /// cap or silently sheds an otherwise admissible event.
    @discardableResult
    func enqueue(
        _ event: Event,
        lane explicitLane: EventPipelineLane? = nil,
        canonicalSHA256: Data? = nil
    ) async -> UInt64? {
        let lane = explicitLane ?? EventPipelineLane.finalLane(for: event)
        guard let outcome = await prepareAndEnqueueBase(
            event,
            lane: lane,
            expectedCanonicalSHA256: canonicalSHA256
        ) else {
            return nil
        }
        return outcome.admission?.generation
    }

    /// Lossless production preparation boundary. Worst-case J workspace is
    /// acquired through FIFO backpressure before sanitizer/JSON allocation,
    /// then shrunk and adopted by the queue's immutable ARC handle.
    func prepareAndEnqueueBase(
        _ event: Event,
        lane explicitLane: EventPipelineLane? = nil,
        expectedCanonicalSHA256: Data? = nil,
        precomputedPreflight: EventJournalIngressPreflight? = nil
    ) async -> JournalBaseEnqueueOutcome? {
        let lane = explicitLane ?? EventPipelineLane.finalLane(for: event)
        let preflight: EventJournalIngressPreflight
        do {
            if let precomputedPreflight {
                preflight = precomputedPreflight
            } else {
                preflight = try EventJournalAdmissionValidator.preflight(event)
            }
        } catch {
            recordRejectedBasePreparation(lane: lane)
            return nil
        }
        guard let workspaceLease = await liveMemoryBudget.acquire(
            bytes: preflight.preparationWorkspaceByteEstimate,
            owner: .journalPrepared
        ) else {
            recordRejectedBasePreparation(lane: lane)
            return nil
        }
        let prepared: EventJournalIngressPreparation
        do {
            prepared = try EventJournalAdmissionValidator.prepare(
                event,
                preflight: preflight
            )
        } catch {
            recordRejectedBasePreparation(lane: lane)
            return nil
        }
        guard prepared.event.id == preflight.eventID,
              expectedCanonicalSHA256 == nil
                || expectedCanonicalSHA256 == prepared.canonicalSHA256 else {
            recordRejectedBasePreparation(lane: lane)
            return nil
        }
        let admission = await enqueuePreparedLosslessly(
            prepared,
            lane: lane,
            adopting: workspaceLease
        )
        return JournalBaseEnqueueOutcome(
            admission: admission,
            sourceRetainedByteEstimate:
                prepared.sourceRetainedByteEstimate,
            poisoned: prepared.overflow != nil
        )
    }

    /// Synchronous compatibility/test seam for already-prepared values. It
    /// cannot await bounded ownership and therefore records an explicit drop
    /// on rejection. Production uses `prepareAndEnqueueBase`, whose async path
    /// drains and backpressures instead.
    @discardableResult
    func enqueuePrepared(
        _ prepared: EventJournalIngressPreparation,
        lane explicitLane: EventPipelineLane? = nil
    ) -> EventJournalAdmission? {
        let event = prepared.event
        let lane = explicitLane ?? EventPipelineLane.finalLane(for: event)
        offeredByLane[lane.rawValue] += 1

        var acquired = ownershipBudget.acquire(prepared)
        while acquired == nil, lane == .priority,
              !buffers[EventPipelineLane.file.rawValue].isEmpty {
            evictNewestQueuedFileForPriorityAdmission()
            acquired = ownershipBudget.acquire(prepared)
        }
        guard let handle = acquired else {
            recordDrop(1, lane: lane)
            return nil
        }
        return admitPreparedHandle(handle, prepared: prepared, lane: lane)
    }

    private func enqueuePreparedLosslessly(
        _ prepared: EventJournalIngressPreparation,
        lane: EventPipelineLane,
        adopting workspaceLease: EventPipelineMemoryLease
    ) async -> EventJournalAdmission? {
        guard ownershipBudget.canEventuallyAdopt(prepared) else {
            offeredByLane[lane.rawValue] += 1
            recordDrop(1, lane: lane)
            return nil
        }
        while !Task.isCancelled {
            if let acquired = ownershipBudget.adopt(
                prepared,
                workspaceLease: workspaceLease
            ) {
                offeredByLane[lane.rawValue] += 1
                return admitPreparedHandle(
                    acquired,
                    prepared: prepared,
                    lane: lane
                )
            }
            // The shared J lease already owns the prepared value, so waiting
            // cannot increase RSS. Force a below-threshold drain and yield the
            // actor until local count/byte ownership becomes available.
            if !draining, hasPendingStorageWork { startDrain() }
            try? await Task.sleep(for: .milliseconds(10))
        }
        offeredByLane[lane.rawValue] += 1
        recordDrop(1, lane: lane)
        return nil
    }

    private func admitPreparedHandle(
        _ handle: EventJournalPreparedHandle,
        prepared: EventJournalIngressPreparation,
        lane: EventPipelineLane
    ) -> EventJournalAdmission? {
        let event = prepared.event
        guard admittedGeneration < UInt64.max else {
            recordDrop(1, lane: lane)
            return nil
        }
        admittedGeneration += 1
        let generation = admittedGeneration
        pendingGenerations.insert(generation)
        eventIDByGeneration[generation] = event.id
        canonicalSHA256ByGeneration[generation] = prepared.canonicalSHA256
        canonicalByteCountByGeneration[generation]
            = prepared.canonicalJSON.count
        buffers[lane.rawValue].append(
            BufferedEvent(generation: generation, handle: handle)
        )
        bufferedBytesByLane[lane.rawValue] += handle.retainedByteCharge
        if bufferDepth + terminalRevisionDepth >= flushThreshold && !draining {
            startDrain()
        }
        return EventJournalAdmission(
            eventID: event.id,
            generation: generation,
            handle: handle
        )
    }

    /// Validator failure occurs before a prepared handle exists, but it still
    /// consumes one offered ingress identity and must remain a visible gap.
    func recordRejectedBasePreparation(lane: EventPipelineLane) {
        offeredByLane[lane.rawValue] += 1
        recordDrop(1, lane: lane)
    }

    func recordRejectedTerminalPreparation(lane: EventPipelineLane) {
        recordTerminalOffered(lane: lane)
        recordTerminalDrop(lane: lane)
    }

    /// Validate both public receipt metadata and the unforgeable internal
    /// handle. The handle may have released its large payload after durable
    /// verification; immutable UUID/digest/byte-count metadata remains.
    private func admissionMetadataMatches(
        _ admission: EventJournalAdmission,
        eventID: UUID
    ) -> Bool {
        guard admission.eventID == eventID,
              admission.generation > 0,
              let baseDigest = admission.canonicalSHA256,
              baseDigest.count == 32,
              admission.canonicalByteCount > 0,
              let baseHandle = admission.preparedHandle,
              !baseHandle.isPoisonedPreparation,
              !baseHandle.isRepairPayloadExpired,
              baseHandle.eventID == admission.eventID,
              baseHandle.canonicalSHA256 == baseDigest,
              baseHandle.canonicalByteCount == admission.canonicalByteCount,
              canonicalSHA256ByGeneration[admission.generation]
                .map({ $0 == baseDigest }) ?? true,
              canonicalByteCountByGeneration[admission.generation]
                .map({ $0 == admission.canonicalByteCount }) ?? true else {
            return false
        }
        if let expectedID = eventIDByGeneration[admission.generation],
           expectedID != admission.eventID {
            return false
        }
        return true
    }

    /// Queue the one final revision for an already-admitted UUID. The overlay
    /// base and terminal handles share one count+byte ownership budget and one
    /// joinable drain, so shutdown owns all final canonical evidence.
    @discardableResult
    func enqueueTerminalRevision(
        _ event: Event,
        lane explicitLane: EventPipelineLane? = nil,
        admission: EventJournalAdmission?,
        canonicalSHA256: Data?
    ) -> TerminalRevisionEnqueueOutcome {
        let lane = explicitLane ?? EventPipelineLane.finalLane(for: event)
        do {
            let prepared = try EventJournalAdmissionValidator.prepare(event)
            guard canonicalSHA256 == nil
                    || canonicalSHA256 == prepared.canonicalSHA256 else {
                recordTerminalOffered(lane: lane)
                recordTerminalDrop(lane: lane)
                return .rejected
            }
            return enqueueTerminalRevision(
                prepared,
                lane: lane,
                admission: admission
            )
        } catch {
            recordTerminalOffered(lane: lane)
            recordTerminalDrop(lane: lane)
            return .rejected
        }
    }

    @discardableResult
    func enqueueTerminalRevision(
        _ prepared: EventJournalIngressPreparation,
        lane explicitLane: EventPipelineLane? = nil,
        admission: EventJournalAdmission?
    ) -> TerminalRevisionEnqueueOutcome {
        let event = prepared.event
        let lane = explicitLane ?? EventPipelineLane.finalLane(for: event)
        recordTerminalOffered(lane: lane)
        guard let admission,
              admissionMetadataMatches(admission, eventID: event.id),
              admission.preparedHandle?.sourceIdentitySHA256
                == prepared.sourceIdentitySHA256,
              let baseDigest = admission.canonicalSHA256 else {
            recordTerminalDrop(lane: lane)
            return .rejected
        }
        let terminalDigest = prepared.canonicalSHA256
        if baseDigest == terminalDigest {
            recordTerminalUnchanged(lane: lane)
            return .unchanged
        }
        guard let handle = ownershipBudget.acquire(prepared) else {
            recordTerminalDrop(lane: lane)
            return .rejected
        }
        terminalRevisionBuffers[lane.rawValue].append(
            BufferedTerminalRevision(
                handle: handle,
                lane: lane,
                admission: admission,
                settlementID: nil
            )
        )
        terminalRevisionBufferedBytesByLane[lane.rawValue]
            += handle.retainedByteCharge
        if bufferDepth + terminalRevisionDepth >= flushThreshold && !draining {
            startDrain()
        }
        return .queued
    }

    /// Prepare and queue a changed terminal value under pre-acquired J credit.
    /// This is the only production path for a full terminal preparation while
    /// storage transitions to the compact EventTerminalDelta API.
    @discardableResult
    func prepareAndEnqueueTerminalRevision(
        _ event: Event,
        lane explicitLane: EventPipelineLane? = nil,
        admission: EventJournalAdmission?
    ) async -> TerminalRevisionEnqueueOutcome {
        let lane = explicitLane ?? EventPipelineLane.finalLane(for: event)
        let preflight: EventJournalIngressPreflight
        do {
            preflight = try EventJournalAdmissionValidator.preflight(event)
        } catch {
            recordRejectedTerminalPreparation(lane: lane)
            return .rejected
        }
        guard let workspaceLease = await liveMemoryBudget.acquire(
            bytes: preflight.preparationWorkspaceByteEstimate,
            owner: .journalPrepared
        ) else {
            recordRejectedTerminalPreparation(lane: lane)
            return .rejected
        }
        let prepared: EventJournalIngressPreparation
        do {
            prepared = try EventJournalAdmissionValidator.prepare(
                event,
                preflight: preflight
            )
        } catch {
            recordRejectedTerminalPreparation(lane: lane)
            return .rejected
        }
        guard prepared.event.id == preflight.eventID else {
            recordRejectedTerminalPreparation(lane: lane)
            return .rejected
        }
        return await enqueueTerminalRevisionLosslessly(
            prepared,
            lane: lane,
            admission: admission,
            adopting: workspaceLease
        )
    }

    /// Queue and join one digest-specific terminal outcome before reviewed
    /// alert fanout. Enqueue alone is not a durability receipt: a crash, sticky
    /// poison, or permanent append failure must become the alert's durable
    /// journal-admission gap rather than a falsely verified base-only context.
    func prepareAndSettleTerminalRevision(
        _ event: Event,
        lane explicitLane: EventPipelineLane? = nil,
        admission: EventJournalAdmission?,
        timeout: Duration = .seconds(5)
    ) async -> EventJournalTerminalAdmission {
        let lane = explicitLane ?? EventPipelineLane.finalLane(for: event)
        func proof(
            prepared: EventJournalIngressPreparation? = nil,
            status: EventJournalContextStatus,
            storageMutationGeneration: UInt64 = 0
        ) -> EventJournalTerminalAdmission {
            EventJournalTerminalAdmission(
                eventID: event.id,
                baseGeneration: admission?.generation ?? 0,
                baseCanonicalSHA256: admission?.canonicalSHA256,
                terminalCanonicalSHA256: prepared?.canonicalSHA256,
                terminalCanonicalByteCount:
                    prepared?.canonicalJSON.count ?? 0,
                status: status,
                storageMutationGeneration: storageMutationGeneration
            )
        }

        let preflight: EventJournalIngressPreflight
        do {
            preflight = try EventJournalAdmissionValidator.preflight(event)
        } catch {
            recordRejectedTerminalPreparation(lane: lane)
            return proof(status: .failed)
        }
        guard let workspaceLease = await liveMemoryBudget.acquire(
            bytes: preflight.preparationWorkspaceByteEstimate,
            owner: .journalPrepared
        ) else {
            recordRejectedTerminalPreparation(lane: lane)
            return proof(status: .dropped)
        }
        let prepared: EventJournalIngressPreparation
        do {
            prepared = try EventJournalAdmissionValidator.prepare(
                event,
                preflight: preflight
            )
        } catch {
            recordRejectedTerminalPreparation(lane: lane)
            return proof(status: .failed)
        }
        guard prepared.event.id == preflight.eventID else {
            recordRejectedTerminalPreparation(lane: lane)
            return proof(prepared: prepared, status: .mismatchedReceipt)
        }

        let settlementID = UUID()
        activeTerminalSettlementIDs.insert(settlementID)
        let outcome = await enqueueTerminalRevisionLosslessly(
            prepared,
            lane: lane,
            admission: admission,
            adopting: workspaceLease,
            settlementID: settlementID
        )
        switch outcome {
        case .rejected:
            activeTerminalSettlementIDs.remove(settlementID)
            terminalSettlementResolutions.removeValue(forKey: settlementID)
            return proof(prepared: prepared, status: .failed)
        case .unchanged:
            activeTerminalSettlementIDs.remove(settlementID)
            terminalSettlementResolutions.removeValue(forKey: settlementID)
            guard let admission else {
                return proof(
                    prepared: prepared,
                    status: .mismatchedReceipt
                )
            }
            let status = await awaitCurrentJournalAdmission(
                admission,
                timeout: timeout,
                securityRelevant: true
            )
            return proof(prepared: prepared, status: status)
        case .queued:
            if !draining { startDrain() }
        }

        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while terminalSettlementResolutions[settlementID] == nil {
            guard !Task.isCancelled, clock.now < deadline else {
                activeTerminalSettlementIDs.remove(settlementID)
                terminalSettlementResolutions.removeValue(
                    forKey: settlementID
                )
                return proof(prepared: prepared, status: .timedOut)
            }
            if !draining { startDrain() }
            try? await Task.sleep(for: .milliseconds(10))
        }
        let resolution = terminalSettlementResolutions.removeValue(
            forKey: settlementID
        )
        activeTerminalSettlementIDs.remove(settlementID)
        guard let resolution else {
            return proof(prepared: prepared, status: .unavailable)
        }
        return proof(
            prepared: prepared,
            status: resolution.status,
            storageMutationGeneration:
                resolution.storageMutationGeneration
        )
    }

    /// Production sparse-terminal path. The raw base/terminal values are used
    /// only while deriving a bounded field delta under pre-acquired J credit;
    /// EventStore receives no full terminal Event and returns the exact
    /// reconstructed terminal digest used by AlertSink's causal barrier.
    func prepareAndSettleTerminalDelta(
        base: Event,
        terminal: Event,
        lane explicitLane: EventPipelineLane? = nil,
        admission: EventJournalAdmission?,
        timeout: Duration = .seconds(5)
    ) async -> EventJournalTerminalAdmission {
        let lane = explicitLane ?? EventPipelineLane.finalLane(for: terminal)
        return await settleTerminalDelta(
            eventID: terminal.id,
            lane: lane,
            admission: admission,
            timeout: timeout
        ) {
            try EventTerminalDeltaValidator.prepare(
                base: base,
                terminal: terminal,
                baseCanonicalSHA256: $0,
                sourceIdentitySHA256: $1
            )
        }
    }

    /// Deferred counterpart. `delta` was composed while each prior raw
    /// revision was still owned by the R/P leases, so replay never retains a
    /// second immutable base Event merely to compute the final overlay.
    func prepareAndSettleTerminalDelta(
        _ delta: EventTerminalDelta,
        lane: EventPipelineLane,
        admission: EventJournalAdmission?,
        timeout: Duration = .seconds(5)
    ) async -> EventJournalTerminalAdmission {
        await settleTerminalDelta(
            eventID: delta.eventID,
            lane: lane,
            admission: admission,
            timeout: timeout
        ) {
            try EventTerminalDeltaValidator.prepare(
                delta: delta,
                baseCanonicalSHA256: $0,
                sourceIdentitySHA256: $1
            )
        }
    }

    private func settleTerminalDelta(
        eventID: UUID,
        lane: EventPipelineLane,
        admission: EventJournalAdmission?,
        timeout: Duration,
        prepare: @Sendable (Data, Data) throws
            -> EventTerminalDeltaPreparation
    ) async -> EventJournalTerminalAdmission {
        func proof(
            status: EventJournalContextStatus,
            terminalDigest: Data? = nil,
            terminalByteCount: Int = 0,
            storageMutationGeneration: UInt64 = 0
        ) -> EventJournalTerminalAdmission {
            EventJournalTerminalAdmission(
                eventID: eventID,
                baseGeneration: admission?.generation ?? 0,
                baseCanonicalSHA256: admission?.canonicalSHA256,
                terminalCanonicalSHA256: terminalDigest,
                terminalCanonicalByteCount: terminalByteCount,
                status: status,
                storageMutationGeneration: storageMutationGeneration
            )
        }

        guard let admission,
              admissionMetadataMatches(admission, eventID: eventID),
              let baseDigest = admission.canonicalSHA256,
              let sourceIdentity = admission.preparedHandle?
                .sourceIdentitySHA256,
              sourceIdentity.count == 32,
              let journalStore else {
            recordTerminalOffered(lane: lane)
            recordTerminalDrop(lane: lane)
            return proof(status: .mismatchedReceipt)
        }
        let baseStatus = await awaitCurrentJournalAdmission(
            admission,
            timeout: timeout,
            securityRelevant: true
        )
        guard baseStatus.isVerified || baseStatus == .prefixIncomplete else {
            recordTerminalOffered(lane: lane)
            recordTerminalDrop(lane: lane)
            return proof(status: baseStatus)
        }
        guard let workspaceLease = await liveMemoryBudget.acquire(
            bytes: EventTerminalDeltaValidator.maximumPreparationWorkspaceBytes,
            owner: .journalPrepared
        ) else {
            recordTerminalOffered(lane: lane)
            recordTerminalDrop(lane: lane)
            return proof(status: .dropped)
        }

        let storagePrepared: EventTerminalDeltaStoragePreparation
        do {
            let prepared = try prepare(baseDigest, sourceIdentity)
            guard prepared.eventID == eventID,
                  prepared.baseCanonicalSHA256 == baseDigest,
                  prepared.sourceIdentitySHA256 == sourceIdentity,
                  prepared.canonicalDeltaSHA256.count == 32,
                  prepared.retainedByteEstimate > 0,
                  prepared.retainedByteEstimate <= workspaceLease.bytes,
                  workspaceLease.resize(
                    to: prepared.retainedByteEstimate
                  ) else {
                recordTerminalOffered(lane: lane)
                recordTerminalDrop(lane: lane)
                return proof(status: .mismatchedReceipt)
            }
            storagePrepared = EventTerminalDeltaStoragePreparation(
                compacting: prepared
            )
        } catch {
            recordTerminalOffered(lane: lane)
            recordTerminalDrop(lane: lane)
            await StorageErrorTracker.shared.recordEventError(error)
            return proof(status: .failed)
        }
        // The typed delta preparation is now out of scope. Shrink its J lease
        // to the compact canonical bytes before transferring the same credit
        // to EventStore's S workspace; storage then owns the only codec lease.
        guard storagePrepared.compactRetainedByteEstimate > 0,
              storagePrepared.compactRetainedByteEstimate
                <= EventPipelineLiveMemoryBudget
                    .productionEventStoreWorkspaceReserveBytes,
              workspaceLease.resize(
                to: storagePrepared.compactRetainedByteEstimate
              ),
              workspaceLease.transfer(to: .eventStoreWorkspace) else {
            recordTerminalOffered(lane: lane)
            recordTerminalDrop(lane: lane)
            return proof(status: .mismatchedReceipt)
        }

        // A concurrent owner can take the J credit released by compaction
        // before this transferred S lease grows to its codec reserve. That is
        // live pressure, not a malformed receipt or terminal evidence loss.
        // Keep the compact digest-bound value charged and wait until S can
        // reclaim its release-valve workspace.
        recordTerminalOffered(lane: lane)
        await terminalDeltaStorageLeaseGrowthHookForTesting?()
        while !Task.isCancelled,
              !workspaceLease.resize(
                to: EventPipelineLiveMemoryBudget
                    .productionEventStoreWorkspaceReserveBytes
              ) {
            recordTerminalRetry(1, lane: lane)
            try? await Task.sleep(for: .milliseconds(10))
        }
        guard !Task.isCancelled else {
            recordTerminalDrop(lane: lane)
            return proof(status: .dropped)
        }

        let inFlightBytes = workspaceLease.bytes
        beginSparseTerminalInFlight(lane: lane, bytes: inFlightBytes)
        defer {
            endSparseTerminalInFlight(lane: lane, bytes: inFlightBytes)
        }
        // Once the exact compact delta and its S lease exist, transient live-
        // memory or SQLite contention is not a terminal evidence result. Keep
        // the causal barrier pending until storage succeeds, a permanent error
        // occurs, or shutdown cancels this task.
        while !Task.isCancelled {
            do {
                let result = try await journalStore.appendTerminalDeltas(
                    preparedDeltas: [storagePrepared],
                    lane: lane,
                    workspaceLease: workspaceLease
                )
                guard result.inputCount == 1,
                      result.outcomes.count == 1,
                      let outcome = result.outcomes.first,
                      outcome.eventID == eventID,
                      outcome.canonicalDeltaSHA256
                        == storagePrepared.canonicalDeltaSHA256 else {
                    recordTerminalDrop(lane: lane)
                    return proof(status: .failed)
                }
                terminalStorageMutationGeneration = max(
                    terminalStorageMutationGeneration,
                    result.storageMutationGeneration
                )
                switch outcome.disposition {
                case .unchangedBase:
                    recordTerminalUnchanged(lane: lane)
                    return proof(
                        status: baseStatus,
                        terminalDigest: outcome.terminalCanonicalSHA256
                            ?? baseDigest,
                        terminalByteCount: outcome.terminalCanonicalByteCount,
                        storageMutationGeneration:
                            result.storageMutationGeneration
                    )
                case .inserted, .alreadyDurable:
                    guard let terminalDigest = outcome.terminalCanonicalSHA256,
                          terminalDigest.count == 32,
                          outcome.terminalCanonicalByteCount > 0 else {
                        recordTerminalDrop(lane: lane)
                        return proof(status: .failed)
                    }
                    recordTerminalDurable(lane: lane)
                    return proof(
                        status: baseStatus,
                        terminalDigest: terminalDigest,
                        terminalByteCount: outcome.terminalCanonicalByteCount,
                        storageMutationGeneration:
                            result.storageMutationGeneration
                    )
                case .poisoned:
                    recordTerminalPoisoned(lane: lane)
                    return proof(
                        status: .poisoned,
                        storageMutationGeneration:
                            result.storageMutationGeneration
                    )
                }
            } catch let error as EventStoreError where isTransient(error) {
                recordTerminalRetry(1, lane: lane)
                try? await Task.sleep(for: .milliseconds(10))
            } catch {
                recordTerminalDrop(lane: lane)
                await StorageErrorTracker.shared.recordEventError(error)
                return proof(status: .failed)
            }
        }
        recordTerminalDrop(lane: lane)
        return proof(status: .dropped)
    }

    private func enqueueTerminalRevisionLosslessly(
        _ prepared: EventJournalIngressPreparation,
        lane: EventPipelineLane,
        admission: EventJournalAdmission?,
        adopting workspaceLease: EventPipelineMemoryLease,
        settlementID: UUID? = nil
    ) async -> TerminalRevisionEnqueueOutcome {
        let event = prepared.event
        recordTerminalOffered(lane: lane)
        guard let admission,
              admissionMetadataMatches(admission, eventID: event.id),
              admission.preparedHandle?.sourceIdentitySHA256
                == prepared.sourceIdentitySHA256,
              let baseDigest = admission.canonicalSHA256 else {
            recordTerminalDrop(lane: lane)
            return .rejected
        }
        if baseDigest == prepared.canonicalSHA256 {
            recordTerminalUnchanged(lane: lane)
            return .unchanged
        }
        guard ownershipBudget.canEventuallyAdopt(prepared) else {
            recordTerminalDrop(lane: lane)
            return .rejected
        }
        var adopted: EventJournalPreparedHandle?
        while adopted == nil, !Task.isCancelled {
            adopted = ownershipBudget.adopt(
                prepared,
                workspaceLease: workspaceLease
            )
            if adopted == nil {
                if !draining, hasPendingStorageWork { startDrain() }
                try? await Task.sleep(for: .milliseconds(10))
            }
        }
        guard let handle = adopted else {
            recordTerminalDrop(lane: lane)
            return .rejected
        }
        terminalRevisionBuffers[lane.rawValue].append(
            BufferedTerminalRevision(
                handle: handle,
                lane: lane,
                admission: admission,
                settlementID: settlementID
            )
        )
        terminalRevisionBufferedBytesByLane[lane.rawValue]
            += handle.retainedByteCharge
        if bufferDepth + terminalRevisionDepth >= flushThreshold && !draining {
            startDrain()
        }
        return .queued
    }

    /// Finish an event whose raw terminal value is exactly the raw base value.
    /// The caller's equality proof avoids a second privacy pass/JSON encoding;
    /// receipt metadata still prevents a forged UUID/generation from settling
    /// terminal conservation as unchanged.
    @discardableResult
    func completeUnchangedTerminalRevision(
        eventID: UUID,
        lane: EventPipelineLane,
        admission: EventJournalAdmission?
    ) -> TerminalRevisionEnqueueOutcome {
        recordTerminalOffered(lane: lane)
        guard let admission,
              admissionMetadataMatches(admission, eventID: eventID) else {
            recordTerminalDrop(lane: lane)
            return .rejected
        }
        recordTerminalUnchanged(lane: lane)
        return .unchanged
    }

    /// A retryable batch failure: SQLITE_BUSY / SQLITE_LOCKED contention, surfaced
    /// distinctly by EventStore as `.busy`. Everything else is permanent.
    private func isTransient(_ e: EventStoreError) -> Bool {
        if case .busy = e { return true }
        return false
    }

    /// Drain the buffer to SQLite in batch transactions until empty.
    /// Reentrancy-safe: each pass snapshots + clears the buffer BEFORE the
    /// `await`, so concurrent `enqueue`s append to a fresh buffer and a second
    /// drain sees it empty and stops. `defer` clears `draining` even on throw.
    /// Admission control: may we consume more disk right now?
    ///
    /// Returns the free-space reading when the floor is breached, nil when the
    /// write is allowed. A failed probe (`freeDiskMB` returns 0) ALLOWS the write
    /// — refusing all telemetry because a `statvfs` call glitched would be a
    /// worse failure than the pressure this guards against.
    private func admissionBlockedFreeMB() -> Int? {
        guard let volumePath, freeSpaceFloorMB > 0 else { return nil }
        let now = ContinuousClock.now
        let freeMB: Int
        if let cached = lastFreeProbe, cached.at.duration(to: now) < .seconds(15) {
            freeMB = cached.freeMB
        } else {
            freeMB = freeDiskMB(forPath: volumePath)
            lastFreeProbe = (at: now, freeMB: freeMB)
        }
        guard freeMB > 0, freeMB < freeSpaceFloorMB else { return nil }
        return freeMB
    }

    private enum TerminalRevisionDrainWork {
        case append(
            lane: EventPipelineLane,
            items: [BufferedTerminalRevision]
        )
        case ensureBase(BufferedTerminalRevision)
        case none
    }

    /// Detach only overlays whose exact base is already durable. A filtered or
    /// previously failed base receives one explicit security-relevant ensure;
    /// a still-pending base remains queued without spinning the actor.
    private func detachTerminalRevisionWork() -> TerminalRevisionDrainWork {
        var ensureCandidate: BufferedTerminalRevision?
        for lane in [EventPipelineLane.priority, .file] {
            let index = lane.rawValue
            guard !terminalRevisionBuffers[index].isEmpty else { continue }
            var appendable: [BufferedTerminalRevision] = []
            var retained: [BufferedTerminalRevision] = []
            appendable.reserveCapacity(terminalRevisionBuffers[index].count)
            retained.reserveCapacity(terminalRevisionBuffers[index].count)

            for item in terminalRevisionBuffers[index] {
                let admission = item.admission
                guard admissionMetadataMatches(
                    admission,
                    eventID: item.event.id
                ) else {
                    recordTerminalDrop(
                        [item],
                        status: .mismatchedReceipt
                    )
                    continue
                }
                guard let resolution = admissionResolutions[
                    admission.generation
                ] else {
                    if admission.generation <= terminalGeneration,
                       !pendingGenerations.contains(admission.generation),
                       ensureCandidate == nil {
                        ensureCandidate = item
                    } else {
                        retained.append(item)
                    }
                    continue
                }
                guard resolution.eventID == admission.eventID else {
                    recordTerminalDrop(
                        [item],
                        status: .mismatchedReceipt
                    )
                    continue
                }
                if resolution.status == .verified {
                    appendable.append(item)
                } else if ensureCandidate == nil {
                    ensureCandidate = item
                } else {
                    retained.append(item)
                }
            }
            terminalRevisionBuffers[index] = retained
            terminalRevisionBufferedBytesByLane[index] = retained.reduce(0) {
                $0 + $1.handle.retainedByteCharge
            }
            if !appendable.isEmpty {
                // Preserve a security-ensure candidate for the next pass.
                if let ensureCandidate {
                    terminalRevisionBuffers[
                        ensureCandidate.lane.rawValue
                    ].insert(
                        ensureCandidate,
                        at: 0
                    )
                    terminalRevisionBufferedBytesByLane[
                        ensureCandidate.lane.rawValue
                    ] += ensureCandidate.handle.retainedByteCharge
                }
                return .append(lane: lane, items: appendable)
            }
        }
        return ensureCandidate.map(TerminalRevisionDrainWork.ensureBase)
            ?? .none
    }

    private func prependTerminalRevisionsForRetry(
        _ items: [BufferedTerminalRevision],
        lane: EventPipelineLane
    ) -> Bool {
        guard !items.isEmpty else { return true }
        terminalRevisionBuffers[lane.rawValue].insert(
            contentsOf: items,
            at: 0
        )
        terminalRevisionBufferedBytesByLane[lane.rawValue] += items.reduce(0) {
            $0 + $1.handle.retainedByteCharge
        }
        return true
    }

    private func processTerminalRevisionWork(
        _ work: TerminalRevisionDrainWork
    ) async -> Bool {
        guard let journalStore else {
            switch work {
            case .append(let lane, let items):
                clearTerminalRevisionInFlight(lane: lane)
                recordTerminalDrop(items, status: .unavailable)
            case .ensureBase(let item):
                clearTerminalRevisionInFlight(lane: item.lane)
                recordTerminalDrop([item], status: .unavailable)
            case .none:
                break
            }
            return true
        }

        switch work {
        case .none:
            return false

        case .ensureBase(let item):
            let admission = item.admission
            guard let handle = admission.preparedHandle,
                  let digest = admission.canonicalSHA256 else {
                clearTerminalRevisionInFlight(lane: item.lane)
                recordTerminalDrop([item], status: .mismatchedReceipt)
                return true
            }
            do {
                let status: EventJournalContextStatus
                if let borrow = handle.borrowPreparation() {
                    // Keep the prepared-value ownership charge live across the
                    // suspended storage call, including every early exit.
                    defer { _ = borrow.preparation.canonicalJSON.count }
                    let base = borrow.preparation
                    let outcome = try await journalStore.ensureJournaled(
                        base,
                        lane: item.lane,
                        reason: .securityRelevant
                    )
                    switch outcome {
                    case .durable(let eventID):
                        status = eventID == admission.eventID
                            ? .verified : .failed
                    case .poisoned(let evidence):
                        status = evidence.originalEventID == admission.eventID
                            ? .poisoned : .failed
                    case .filtered(let eventID):
                        status = eventID == admission.eventID
                            ? .filtered : .failed
                    }
                } else {
                    let verification = try await journalStore.verifyJournaled(
                        eventID: admission.eventID,
                        canonicalSHA256: digest
                    )
                    switch verification.disposition {
                    case .durable(let eventID):
                        status = eventID == admission.eventID
                            ? .verified : .failed
                    case .poisoned(let evidence):
                        status = evidence.originalEventID == admission.eventID
                            ? .poisoned : .failed
                    case .missing(let eventID), .conflict(let eventID):
                        status = eventID == admission.eventID
                            ? .failed : .mismatchedReceipt
                    }
                }
                clearTerminalRevisionInFlight(lane: item.lane)
                let settledStatus = handle.isRepairPayloadExpired
                    && status != .poisoned ? .repairExpired : status
                guard settledStatus == .verified else {
                    recordTerminalDrop([item], status: settledStatus)
                    return true
                }
                admissionResolutions[admission.generation]
                    = JournalAdmissionResolution(
                        eventID: admission.eventID,
                        status: .verified
                    )
                handle.compactAfterDurableVerification()
                repairJournalGap(generation: admission.generation)
                guard prependTerminalRevisionsForRetry(
                    [item],
                    lane: item.lane
                ) else {
                    recordTerminalDrop([item])
                    return true
                }
            } catch let error as EventStoreError where isTransient(error) {
                clearTerminalRevisionInFlight(lane: item.lane)
                if prependTerminalRevisionsForRetry([item], lane: item.lane) {
                    recordTerminalRetry(1, lane: item.lane)
                    return false
                }
                recordTerminalDrop([item])
                await StorageErrorTracker.shared.recordEventError(error)
            } catch {
                clearTerminalRevisionInFlight(lane: item.lane)
                recordTerminalDrop([item])
                await StorageErrorTracker.shared.recordEventError(error)
            }
            return true

        case .append(let lane, let items):
            do {
                let result = try await journalStore.appendTerminalRevisions(
                    preparedEvents: items.map(\.handle.preparation),
                    lane: lane
                )
                clearTerminalRevisionInFlight(lane: lane)
                terminalStorageMutationGeneration = max(
                    terminalStorageMutationGeneration,
                    result.storageMutationGeneration
                )
                guard result.inputCount == items.count,
                      result.outcomes.count == items.count,
                      zip(items, result.outcomes).allSatisfy({ item, outcome in
                          terminalRevisionOutcomeID(outcome) == item.event.id
                      }) else {
                    recordTerminalDrop(items)
                    return true
                }
                for (item, outcome) in zip(items, result.outcomes) {
                    recordTerminalOutcome(
                        outcome,
                        for: item,
                        storageMutationGeneration:
                            result.storageMutationGeneration
                    )
                }
                return true
            } catch let partial as EventTerminalRevisionBatchFailure {
                clearTerminalRevisionInFlight(lane: lane)
                terminalStorageMutationGeneration = max(
                    terminalStorageMutationGeneration,
                    partial.progress.storageMutationGeneration
                )
                let committedCount = partial.progress.outcomes.count
                guard committedCount <= items.count,
                      zip(
                        items.prefix(committedCount),
                        partial.progress.outcomes
                      ).allSatisfy({ item, outcome in
                          terminalRevisionOutcomeID(outcome) == item.event.id
                      }),
                      partial.uncommittedEvents
                        == items.dropFirst(committedCount).map(\.event) else {
                    recordTerminalDrop(items)
                    await StorageErrorTracker.shared.recordEventError(
                        partial.underlyingError
                    )
                    return true
                }
                for (item, outcome) in zip(
                    items,
                    partial.progress.outcomes
                ) {
                    recordTerminalOutcome(
                        outcome,
                        for: item,
                        storageMutationGeneration:
                            partial.progress.storageMutationGeneration
                    )
                }
                let remainder = Array(items.dropFirst(committedCount))
                let transient = (partial.underlyingError as? EventStoreError)
                    .map(isTransient) ?? false
                if transient {
                    if prependTerminalRevisionsForRetry(
                        remainder,
                        lane: lane
                    ) {
                        recordTerminalRetry(remainder.count, lane: lane)
                        return false
                    }
                }
                recordTerminalDrop(remainder)
                await StorageErrorTracker.shared.recordEventError(
                    partial.underlyingError
                )
                return true
            } catch let error as EventStoreError where isTransient(error) {
                clearTerminalRevisionInFlight(lane: lane)
                if prependTerminalRevisionsForRetry(items, lane: lane) {
                    recordTerminalRetry(items.count, lane: lane)
                    return false
                }
                recordTerminalDrop(items)
                await StorageErrorTracker.shared.recordEventError(error)
                return true
            } catch {
                clearTerminalRevisionInFlight(lane: lane)
                recordTerminalDrop(items)
                await StorageErrorTracker.shared.recordEventError(error)
                return true
            }
        }
    }

    private func terminalRevisionOutcomeID(
        _ outcome: EventTerminalRevisionOutcome
    ) -> UUID {
        switch outcome {
        case .unchangedBase(let eventID), .inserted(let eventID),
             .alreadyDurable(let eventID):
            return eventID
        case .poisoned(let evidence):
            return evidence.originalEventID
        }
    }

    private func insertBaseBatch(
        _ batch: [BufferedEvent],
        lane: EventPipelineLane
    ) async throws -> EventBatchInsertResult {
        if let preparedStore = store as? any EventPreparedBatchInserting {
            return try await preparedStore.insert(
                preparedEvents: batch.map(\.handle.preparation),
                lane: lane
            )
        }
        return try await store.insert(
            events: batch.map(\.event),
            lane: lane
        )
    }

    private func recordTerminalOutcome(
        _ outcome: EventTerminalRevisionOutcome,
        for item: BufferedTerminalRevision,
        storageMutationGeneration: UInt64
    ) {
        switch outcome {
        case .unchangedBase:
            recordTerminalUnchanged(lane: item.lane)
            resolveTerminalSettlement(
                item,
                status: .verified,
                storageMutationGeneration: storageMutationGeneration
            )
        case .inserted, .alreadyDurable:
            recordTerminalDurable(lane: item.lane)
            resolveTerminalSettlement(
                item,
                status: .verified,
                storageMutationGeneration: storageMutationGeneration
            )
        case .poisoned:
            recordTerminalPoisoned(lane: item.lane)
            resolveTerminalSettlement(
                item,
                status: .poisoned,
                storageMutationGeneration: storageMutationGeneration
            )
        }
    }

    private func drain() async {
        defer {
            draining = false
            drainTask = nil
        }
        while hasPendingStorageWork {
            let terminalWork = detachTerminalRevisionWork()
            if case .none = terminalWork {
                // No terminal overlay is currently eligible; advance its base.
            } else {
                switch terminalWork {
                case .append(let lane, let items):
                    setTerminalRevisionInFlight(items, lane: lane)
                case .ensureBase(let item):
                    setTerminalRevisionInFlight([item], lane: item.lane)
                case .none:
                    break
                }
                let shouldContinue = await processTerminalRevisionWork(
                    terminalWork
                )
                switch terminalWork {
                case .append(let lane, _):
                    clearTerminalRevisionInFlight(lane: lane)
                case .ensureBase(let item):
                    clearTerminalRevisionInFlight(lane: item.lane)
                case .none:
                    break
                }
                if !shouldContinue { return }
                continue
            }
            guard bufferDepth > 0 else {
                // Every remaining overlay is waiting for an admission outcome
                // that cannot advance in this task. Leave it visible for the
                // next flush rather than spinning.
                return
            }
            // Disk admission check BEFORE the write, not after SQLite fails. Shed
            // the batch and stop the pass; the periodic flush loop retries, so
            // ingestion resumes by itself once the retention sweeps free space.
            if let freeMB = admissionBlockedFreeMB() {
                let priorityRows = buffers[EventPipelineLane.priority.rawValue]
                let fileRows = buffers[EventPipelineLane.file.rawValue]
                let priorityShed = priorityRows.count
                let fileShed = fileRows.count
                buffers[EventPipelineLane.priority.rawValue].removeAll(keepingCapacity: true)
                buffers[EventPipelineLane.file.rawValue].removeAll(keepingCapacity: true)
                bufferedBytesByLane[EventPipelineLane.priority.rawValue] = 0
                bufferedBytesByLane[EventPipelineLane.file.rawValue] = 0
                recordDrop(priorityShed, lane: .priority)
                recordDrop(fileShed, lane: .file)
                markTerminal(priorityRows)
                markTerminal(fileRows)
                let shed = priorityShed + fileShed
                if !admissionBlocked {
                    admissionBlocked = true
                    Logger(subsystem: "com.maccrab.agentkit", category: "storage")
                        .fault("Storage admission BLOCKED: only \(freeMB, privacy: .public) MB free on the store volume (floor \(self.freeSpaceFloorMB, privacy: .public) MB). Event persistence is PAUSED and \(shed, privacy: .public) buffered events were shed to protect the volume. Detection continues in memory; the forensic record has a gap until space is reclaimed.")
                }
                return
            }
            if admissionBlocked {
                admissionBlocked = false
                Logger(subsystem: "com.maccrab.agentkit", category: "storage")
                    .notice("Storage admission restored — free space back above the floor; event persistence resumed.")
            }
            guard let detached = detachNextBatch() else { return }
            let lane = detached.lane
            let batch = detached.events
            setInFlight(batch, lane: lane)
            do {
                let result = try await insertBaseBatch(batch, lane: lane)
                recordPersisted(result.persistedCount, lane: lane)
                recordFiltered(result.filteredCount, lane: lane)
                recordPoisoned(poisonedCount(in: result), lane: lane)
                markTerminal(batch, result: result)
                clearInFlight(lane: lane)
            } catch let partial as EventBatchInsertFailure {
                let transient = (partial.underlyingError as? EventStoreError)
                    .map(isTransient) ?? false
                let retryable = partial.replacementReadyForRetry || transient
                guard let disposition = partitionPartialFailure(
                    batch,
                    progress: partial.progress,
                    uncommittedEvents: partial.uncommittedEvents
                ), disposition.terminal.count
                    == partial.progress.persistedCount
                        + partial.progress.filteredCount
                        + poisonedCount(in: partial.progress),
                    partial.progress.inputDispositions.count
                        == batch.count else {
                    // Never guess at identity from malformed aggregate counts.
                    // Retrying the complete batch is safe on a transient or a
                    // fresh replacement because immutable event IDs make the
                    // already-durable portion duplicate no-ops.
                    if retryable, prependForRetry(batch, lane: lane) {
                        clearInFlight(lane: lane)
                        return
                    }
                    recordDrop(batch.count, lane: lane)
                    markTerminal(batch, status: .failed)
                    clearInFlight(lane: lane)
                    await StorageErrorTracker.shared.recordEventError(
                        partial.underlyingError
                    )
                    continue
                }
                recordPersisted(partial.progress.persistedCount, lane: lane)
                recordFiltered(partial.progress.filteredCount, lane: lane)
                recordPoisoned(
                    poisonedCount(in: partial.progress),
                    lane: lane
                )
                markTerminal(
                    batch,
                    result: partial.progress,
                    allowUncommitted: true
                )
                if partial.replacementReadyForRetry {
                    // Corruption recovery quarantined the DB containing any
                    // earlier committed chunks. EventStore resets progress and
                    // returns every exact filter-passing candidate; filtered
                    // envelopes are terminal while those candidates retry.
                    if prependForRetry(disposition.uncommitted, lane: lane) {
                        clearInFlight(lane: lane)
                        return
                    }
                } else if transient {
                    // Only the exact rolled-back/unstarted identities retry.
                    // Arbitrarily-positioned filtered rows are already terminal
                    // and must never be substituted by a positional suffix.
                    if prependForRetry(disposition.uncommitted, lane: lane) {
                        clearInFlight(lane: lane)
                        return
                    }
                }
                // Complete the ownership transition before reporting the error:
                // StorageErrorTracker is an actor hop, and heartbeat snapshots
                // must never observe rows in neither in-flight nor drop/retry/
                // persisted accounting while that hop is suspended.
                recordDrop(disposition.uncommitted.count, lane: lane)
                markTerminal(disposition.uncommitted, status: .failed)
                clearInFlight(lane: lane)
                await StorageErrorTracker.shared.recordEventError(
                    partial.underlyingError
                )
            } catch let e as EventStoreError where isTransient(e) {
                // #13: TRANSIENT contention (SQLITE_BUSY/LOCKED) — typically a
                // reader pinning the WAL past the 5s busy_timeout. Retrying the
                // SAME batch succeeds once the contention clears, so DON'T drop it:
                // re-queue at the front and stop this pass. The periodic flush loop
                // retries after its interval (a natural backoff). The detached
                // handles retain their existing reservations, so reattachment
                // stays within the hard cap without evicting newer ownership.
                // This is the leading (previously-misattributed) cause of the
                // external audit's get_events-returns-0 under WAL contention.
                if prependForRetry(batch, lane: lane) {
                    clearInFlight(lane: lane)
                    return
                }
                recordDrop(batch.count, lane: lane)
                markTerminal(batch, status: .dropped)
                clearInFlight(lane: lane)
                await StorageErrorTracker.shared.recordEventError(e)
            } catch {
                // PERMANENT (disk full, corruption, encoding) — retrying the same
                // transaction would just fail again. Record the error AND count the
                // lost events as storage-write drops so they are not silently
                // uncounted: `droppedCount` reflects hard-cap overflow, an
                // unretryable transient, and permanent flush failures.
                recordDrop(batch.count, lane: lane)
                markTerminal(batch, status: .failed)
                clearInFlight(lane: lane)
                await StorageErrorTracker.shared.recordEventError(error)
            }
        }
    }

    /// Start the periodic partial-flush loop. Under a low event rate the buffer
    /// may never reach `flushThreshold`, so this timer flushes whatever has
    /// accumulated on a fixed cadence — bounding write latency to `intervalMs`.
    /// Idempotent.
    func startFlushLoop(intervalMs: UInt64 = 250) {
        guard flushLoop == nil else { return }
        flushLoop = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: intervalMs * 1_000_000)
                await self?.flushPartial()
            }
        }
    }

    /// Capture the writer generation admitted before an alert's evidence job.
    /// A generation is assigned only after the bounded queue accepts the row;
    /// queue-cap rejection remains visible through ordinary drop telemetry.
    func evidencePrefixGeneration() -> UInt64 {
        admittedGeneration
    }

    /// Resolve one identity-bound base receipt. This is deliberately stronger
    /// than `awaitEvidencePrefix`: terminal writer ownership is not synonymous
    /// with durable canonical evidence. Current filtered/dropped/failed rows
    /// retain their exact status; only an earlier dropped/failed admission turns
    /// an otherwise-durable current trigger into `.prefixIncomplete`.
    func awaitJournalAdmission(
        _ receipt: EventJournalAdmission,
        timeout: Duration = .seconds(2)
    ) async -> EventJournalContextStatus {
        let current = await awaitCurrentJournalAdmission(
            receipt,
            timeout: timeout,
            securityRelevant: true
        )
        guard current == .verified else { return current }
        if let gap = earliestJournalGapGeneration,
           gap < receipt.generation {
            return .prefixIncomplete
        }
        return .verified
    }

    /// Universal event-bearing AlertSink path for producers outside EventLoop.
    /// Snapshot the already-admitted prefix first, then ask EventStore to insert
    /// or validate this exact Event value. Later admissions are unrelated and
    /// never extend this precommit barrier.
    func ensureJournalAdmission(
        _ event: Event,
        timeout: Duration = .seconds(2)
    ) async -> EventJournalContextStatus {
        let preflight: EventJournalIngressPreflight
        do {
            preflight = try EventJournalAdmissionValidator.preflight(event)
        } catch {
            return .failed
        }
        guard let workspaceLease = await liveMemoryBudget.acquire(
            bytes: preflight.preparationWorkspaceByteEstimate,
            owner: .journalPrepared
        ) else {
            return .dropped
        }
        let prepared: EventJournalIngressPreparation
        do {
            prepared = try EventJournalAdmissionValidator.prepare(
                event,
                preflight: preflight
            )
        } catch {
            return .failed
        }
        guard prepared.event.id == preflight.eventID,
              let preparedHandle = ownershipBudget.adopt(
                prepared,
                workspaceLease: workspaceLease
              ) else {
            return .dropped
        }
        let prefix = admittedGeneration
        if prefix > terminalGeneration {
            let settled = await awaitEvidencePrefix(
                through: prefix,
                timeout: timeout
            )
            guard settled else { return .timedOut }
        }
        guard let journalStore else { return .unavailable }
        let current: EventJournalContextStatus
        do {
            let outcome = try await journalStore.ensureJournaled(
                preparedHandle.preparation,
                lane: EventPipelineLane.finalLane(for: event),
                reason: .securityRelevant
            )
            switch outcome {
            case .durable(let eventID):
                current = eventID == event.id ? .verified : .failed
            case .poisoned(let evidence):
                current = evidence.originalEventID == event.id
                    ? .poisoned : .failed
            case .filtered(let eventID):
                current = eventID == event.id ? .filtered : .failed
            }
        } catch {
            await StorageErrorTracker.shared.recordEventError(error)
            return .failed
        }
        guard current == .verified else { return current }
        if let gap = earliestJournalGapGeneration, gap <= prefix {
            return .prefixIncomplete
        }
        return .verified
    }

    /// Projection promotion is review-only and never mutates the immutable
    /// journal base. A prior unrelated context gap does not prevent promotion;
    /// the current UUID itself must nevertheless be durable.
    @discardableResult
    func promoteProjection(
        event: Event,
        reviewedMatches: [RuleMatch],
        admission: EventJournalAdmission?
    ) async -> Bool {
        let reviewed = ReviewedRuleMatches.normalized(reviewedMatches)
        guard !reviewed.isEmpty, let journalStore else { return false }
        if let admission {
            guard admission.eventID == event.id,
                  await awaitCurrentJournalAdmission(
                    admission,
                    timeout: .seconds(2),
                    securityRelevant: true
                  ) == .verified else {
                return false
            }
        } else {
            let current = await ensureJournalAdmission(event)
            guard current == .verified || current == .prefixIncomplete else {
                return false
            }
        }
        do {
            _ = try await journalStore.promoteProjection(
                eventID: event.id,
                reviewedMatches: reviewed
            )
            return true
        } catch {
            await StorageErrorTracker.shared.recordEventError(error)
            return false
        }
    }

    private func awaitCurrentJournalAdmission(
        _ receipt: EventJournalAdmission,
        timeout: Duration,
        securityRelevant: Bool = false
    ) async -> EventJournalContextStatus {
        sweepRepairPayloadLeases()
        guard receipt.generation > 0 else { return .mismatchedReceipt }
        guard let receiptDigest = receipt.canonicalSHA256,
              receiptDigest.count == 32,
              receipt.canonicalByteCount > 0 else {
            return .mismatchedReceipt
        }
        if let expected = eventIDByGeneration[receipt.generation],
           expected != receipt.eventID {
            return .mismatchedReceipt
        }
        if let expectedDigest = canonicalSHA256ByGeneration[receipt.generation],
           expectedDigest != receiptDigest {
            return .mismatchedReceipt
        }
        if let expectedBytes = canonicalByteCountByGeneration[
            receipt.generation
        ], expectedBytes != receipt.canonicalByteCount {
            return .mismatchedReceipt
        }
        if let handle = receipt.preparedHandle {
            guard handle.eventID == receipt.eventID,
                  handle.canonicalSHA256 == receiptDigest,
                  handle.canonicalByteCount == receipt.canonicalByteCount else {
                return .mismatchedReceipt
            }
            guard !handle.isRepairPayloadExpired else {
                return .repairExpired
            }
        }
        if let resolution = admissionResolutions[receipt.generation] {
            guard resolution.eventID == receipt.eventID else {
                return .mismatchedReceipt
            }
            return await ensureSecurityRelevantAdmissionIfNeeded(
                resolution.status,
                receipt: receipt,
                securityRelevant: securityRelevant
            )
        }
        guard receipt.generation <= admittedGeneration else {
            return .mismatchedReceipt
        }
        if eventIDByGeneration[receipt.generation] == nil,
           !pendingGenerations.contains(receipt.generation) {
            guard let handle = receipt.preparedHandle,
                  let journalStore else { return .mismatchedReceipt }
            do {
                if let borrow = handle.borrowPreparation() {
                    // ARC may otherwise release a last-use-only borrow before
                    // this async storage operation returns, under-accounting
                    // the still-live copied preparation.
                    defer { _ = borrow.preparation.canonicalJSON.count }
                    let prepared = borrow.preparation
                    let outcome = try await journalStore.ensureJournaled(
                        prepared,
                        lane: EventPipelineLane.finalLane(for: prepared.event),
                        reason: securityRelevant
                            ? .securityRelevant : .ordinary
                    )
                    switch outcome {
                    case .durable(let eventID):
                        guard eventID == receipt.eventID else { return .failed }
                        guard !handle.isRepairPayloadExpired else {
                            return .repairExpired
                        }
                        handle.compactAfterDurableVerification()
                        return .verified
                    case .poisoned(let evidence):
                        return evidence.originalEventID == receipt.eventID
                            ? .poisoned : .failed
                    case .filtered(let eventID):
                        guard !handle.isRepairPayloadExpired else {
                            return .repairExpired
                        }
                        return eventID == receipt.eventID
                            ? .filtered : .failed
                    }
                }
                let verification = try await journalStore.verifyJournaled(
                    eventID: receipt.eventID,
                    canonicalSHA256: receiptDigest
                )
                switch verification.disposition {
                case .durable(let eventID):
                    return eventID == receipt.eventID ? .verified : .failed
                case .poisoned(let evidence):
                    return evidence.originalEventID == receipt.eventID
                        ? .poisoned : .failed
                case .missing(let eventID), .conflict(let eventID):
                    return eventID == receipt.eventID
                        ? .mismatchedReceipt : .failed
                }
            } catch {
                await StorageErrorTracker.shared.recordEventError(error)
                return .failed
            }
        }
        guard eventIDByGeneration[receipt.generation] == receipt.eventID else {
            return .mismatchedReceipt
        }

        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        if !draining, bufferDepth > 0 { startDrain() }
        while admissionResolutions[receipt.generation] == nil {
            guard !Task.isCancelled, clock.now < deadline else {
                return .timedOut
            }
            try? await Task.sleep(for: .milliseconds(10))
            if !draining, bufferDepth > 0 { startDrain() }
        }
        guard let resolution = admissionResolutions[receipt.generation] else {
            return .unavailable
        }
        guard resolution.eventID == receipt.eventID else {
            return .mismatchedReceipt
        }
        return await ensureSecurityRelevantAdmissionIfNeeded(
            resolution.status,
            receipt: receipt,
            securityRelevant: securityRelevant
        )
    }

    private func ensureSecurityRelevantAdmissionIfNeeded(
        _ status: EventJournalContextStatus,
        receipt: EventJournalAdmission,
        securityRelevant: Bool
    ) async -> EventJournalContextStatus {
        guard securityRelevant,
              status == .filtered || status == .dropped
                || status == .failed || status == .unavailable else {
            return status
        }
        guard let handle = receipt.preparedHandle,
              handle.eventID == receipt.eventID,
              !handle.isPoisonedPreparation,
              !handle.isRepairPayloadExpired,
              let borrow = handle.borrowPreparation(),
              let journalStore else {
            return status
        }
        let prepared = borrow.preparation
        // The defer captures `borrow` strongly through the awaited call and
        // all guarded returns so compaction cannot release its memory credit
        // while EventStore still owns the value argument.
        defer { _ = borrow.preparation.canonicalJSON.count }
        do {
            let outcome = try await journalStore.ensureJournaled(
                prepared,
                lane: EventPipelineLane.finalLane(for: prepared.event),
                reason: .securityRelevant
            )
            if case .poisoned(let evidence) = outcome {
                return evidence.originalEventID == receipt.eventID
                    ? .poisoned : .failed
            }
            guard !handle.isRepairPayloadExpired else {
                return .repairExpired
            }
            guard case .durable(let eventID) = outcome,
                  eventID == receipt.eventID else {
                return status
            }
            admissionResolutions[receipt.generation]
                = JournalAdmissionResolution(
                    eventID: eventID,
                    status: .verified
                )
            handle.compactAfterDurableVerification()
            repairJournalGap(generation: receipt.generation)
            return .verified
        } catch {
            await StorageErrorTracker.shared.recordEventError(error)
            return .failed
        }
    }

    private func repairJournalGap(generation: UInt64) {
        repairableJournalGapGenerations.remove(generation)
        repairPayloadLeases.removeValue(forKey: generation)
    }

    /// Wait a bounded interval for every admitted generation through `target`
    /// to reach persisted, filtered, or explicitly-dropped terminal state.
    /// This preserves batching: the wait joins the ordinary drain rather than
    /// issuing a per-alert SQLite transaction. False is an honest context gap;
    /// AlertSink still retains the request's bounded triggering-event snapshot.
    func awaitEvidencePrefix(
        through target: UInt64,
        timeout: Duration = .seconds(2)
    ) async -> Bool {
        guard target > terminalGeneration else { return true }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        if !draining, bufferDepth > 0 {
            startDrain()
        }
        while terminalGeneration < target {
            guard !Task.isCancelled, clock.now < deadline else {
                return false
            }
            try? await Task.sleep(for: .milliseconds(10))
            if !draining, bufferDepth > 0 {
                startDrain()
            }
        }
        return true
    }

    /// Flush a below-threshold partial batch (called by the timer + on shutdown).
    func flushPartial() async {
        sweepRepairPayloadLeases()
        if let task = drainTask {
            await task.value
            return
        }
        if hasPendingStorageWork {
            startDrain()
            if let task = drainTask {
                await task.value
            }
        }
    }

    /// Stop the timer and flush anything still buffered. Call on graceful
    /// daemon teardown so the last partial batch reaches disk.
    func shutdown() async {
        let timer = flushLoop
        flushLoop = nil
        timer?.cancel()
        await timer?.value

        // A threshold-triggered drain is independent of the timer. Join it too
        // before the final partial pass, then capture anything queued between
        // those joins and this actor turn.
        if let task = drainTask {
            await task.value
        }
        await flushPartial()
    }

    private func startDrain() {
        guard !draining, drainTask == nil, hasPendingStorageWork else {
            return
        }
        draining = true
        drainTask = Task { [weak self] in
            await self?.drain()
        }
    }
}
