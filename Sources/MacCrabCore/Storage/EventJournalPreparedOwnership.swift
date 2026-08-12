import Foundation

/// Scoped ownership of one full prepared value. The parent handle cannot
/// shrink its process-wide credit while a storage repair call is suspended
/// with this value, closing the expiry-vs-actor-reentrancy accounting race.
package final class EventJournalPreparedBorrow: @unchecked Sendable {
    package let preparation: EventJournalIngressPreparation
    private let handle: EventJournalPreparedHandle

    fileprivate init(
        preparation: EventJournalIngressPreparation,
        handle: EventJournalPreparedHandle
    ) {
        self.preparation = preparation
        self.handle = handle
    }

    deinit { handle.releasePreparationBorrow() }
}

/// One immutable, reference-counted ownership of a prepared journal value.
/// Copies of an admission receipt and TaskLocal inheritance share this object,
/// so the sanitized Event graph and canonical bytes are retained once rather
/// than copied into every advisory/detection child task.
package final class EventJournalPreparedHandle: @unchecked Sendable {
    private enum PendingCompaction {
        case durable
        case repairExpired
    }

    package let eventID: UUID
    package let canonicalSHA256: Data
    package let canonicalByteCount: Int
    package let sourceIdentitySHA256: Data
    package let isPoisonedPreparation: Bool

    private let lock = NSLock()
    private var storedPreparation: EventJournalIngressPreparation?
    private var chargedBytes: Int
    private var repairPayloadExpired = false
    private var activePreparationBorrows = 0
    private var pendingCompaction: PendingCompaction?

    private let budget: EventJournalPreparedOwnershipBudget
    private let liveMemoryLease: EventPipelineMemoryLease

    fileprivate init(
        preparation: EventJournalIngressPreparation,
        retainedByteCharge: Int,
        budget: EventJournalPreparedOwnershipBudget,
        liveMemoryLease: EventPipelineMemoryLease
    ) {
        self.eventID = preparation.event.id
        self.canonicalSHA256 = preparation.canonicalSHA256
        self.canonicalByteCount = preparation.canonicalJSON.count
        self.sourceIdentitySHA256 = preparation.sourceIdentitySHA256
        self.isPoisonedPreparation = preparation.overflow != nil
        self.storedPreparation = preparation
        self.chargedBytes = retainedByteCharge
        self.budget = budget
        self.liveMemoryLease = liveMemoryLease
    }

    /// Full prepared ownership exists until the writer has an identity-bound
    /// durable outcome. Filtered/failed candidates deliberately keep it so a
    /// later security-relevant alert can repair the exact value. Once durable,
    /// `compactAfterDurableVerification` drops Event+JSON while receipts retain
    /// only immutable identity metadata.
    package var availablePreparation: EventJournalIngressPreparation? {
        lock.lock()
        let value = pendingCompaction == nil ? storedPreparation : nil
        lock.unlock()
        return value
    }

    package func borrowPreparation() -> EventJournalPreparedBorrow? {
        lock.lock()
        guard pendingCompaction == nil,
              !repairPayloadExpired,
              let preparation = storedPreparation else {
            lock.unlock()
            return nil
        }
        activePreparationBorrows += 1
        lock.unlock()
        return EventJournalPreparedBorrow(
            preparation: preparation,
            handle: self
        )
    }

    /// Queue/in-flight code accesses this only while it owns the uncompacted
    /// handle. Receipt consumers must use `availablePreparation` because a
    /// verified base may already have compacted.
    package var preparation: EventJournalIngressPreparation {
        lock.lock()
        defer { lock.unlock() }
        precondition(
            storedPreparation != nil,
            "durable journal receipt no longer owns prepared payload"
        )
        return storedPreparation!
    }

    package var retainedByteCharge: Int {
        lock.lock()
        let value = chargedBytes
        lock.unlock()
        return value
    }

    /// True only when a non-durable repair payload outlived the bounded repair
    /// lease. A compact durable receipt remains re-verifiable through storage;
    /// an expired repair receipt must never be upgraded to verified by late
    /// child work that no longer owns the exact prepared value.
    package var isRepairPayloadExpired: Bool {
        lock.lock()
        let value = repairPayloadExpired
        lock.unlock()
        return value
    }

    /// Release the large prepared Event/JSON graph after EventStore proves the
    /// immutable base durable. ARC-shared TaskLocal receipts keep this handle,
    /// but they now cost a fixed metadata charge and revalidate through the
    /// compact EventStore locator if their bounded generation history ages out.
    package func compactAfterDurableVerification() {
        compact(expiredRepairPayload: false)
    }

    /// Release a filtered/failed prepared value after its repair window. The
    /// identity metadata survives, but callers can distinguish this from a
    /// compact durable receipt and fail closed.
    @discardableResult
    package func compactAfterRepairExpiry() -> Bool {
        compact(expiredRepairPayload: true)
    }

    @discardableResult
    private func compact(expiredRepairPayload: Bool) -> Bool {
        lock.lock()
        guard storedPreparation != nil else {
            if expiredRepairPayload { repairPayloadExpired = true }
            lock.unlock()
            return false
        }
        if expiredRepairPayload { repairPayloadExpired = true }
        if activePreparationBorrows > 0 {
            if expiredRepairPayload || pendingCompaction == nil {
                pendingCompaction = expiredRepairPayload
                    ? .repairExpired : .durable
            }
            lock.unlock()
            return true
        }
        let oldCharge = chargedBytes
        storedPreparation = nil
        repairPayloadExpired = expiredRepairPayload
        pendingCompaction = nil
        chargedBytes = EventJournalPreparedOwnershipBudget
            .compactReceiptByteCharge
        let newCharge = chargedBytes
        lock.unlock()
        precondition(liveMemoryLease.resize(to: newCharge))
        budget.resize(from: oldCharge, to: newCharge)
        return true
    }

    fileprivate func releasePreparationBorrow() {
        var transition: (old: Int, new: Int)?
        lock.lock()
        activePreparationBorrows = max(0, activePreparationBorrows - 1)
        if activePreparationBorrows == 0,
           pendingCompaction != nil,
           storedPreparation != nil {
            let oldCharge = chargedBytes
            storedPreparation = nil
            chargedBytes = EventJournalPreparedOwnershipBudget
                .compactReceiptByteCharge
            pendingCompaction = nil
            transition = (oldCharge, chargedBytes)
        }
        lock.unlock()
        if let transition {
            precondition(liveMemoryLease.resize(to: transition.new))
            budget.resize(from: transition.old, to: transition.new)
        }
    }

    deinit {
        lock.lock()
        let bytes = chargedBytes
        let countedAsPrepared = storedPreparation != nil
        lock.unlock()
        budget.release(bytes: bytes, countedAsPrepared: countedAsPrepared)
    }
}

/// Synchronous lock-backed budget because ARC releases can occur on any task
/// or executor. It accounts each immutable handle once across writer queues,
/// SQLite in-flight calls, TaskLocal receipts, and deferred replay ownership.
package final class EventJournalPreparedOwnershipBudget: @unchecked Sendable {
    /// UUID, generation-bound digest metadata, object/lock overhead, and
    /// allocator slack. Deliberately conservative for the compact receipt.
    package static let compactReceiptByteCharge = 256
    package static let productionMaximumLiveHandles = 20_000
    package static let productionCompactReceiptReserveBytes =
        productionMaximumLiveHandles * compactReceiptByteCharge

    package struct Snapshot: Sendable, Equatable {
        package let retainedCount: Int
        package let compactReceiptCount: Int
        package let liveHandleCount: Int
        package let retainedBytes: Int
        package let maximumCount: Int
        package let maximumBytes: Int
    }

    private let lock = NSLock()
    private let maximumCount: Int
    private let maximumBytes: Int
    private let liveMemoryBudget: EventPipelineLiveMemoryBudget
    private var retainedCount = 0
    private var compactReceiptCount = 0
    private var retainedBytes = 0

    package init(
        maximumCount: Int,
        maximumBytes: Int,
        liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared
    ) {
        self.maximumCount = max(1, maximumCount)
        self.maximumBytes = max(1, maximumBytes)
        self.liveMemoryBudget = liveMemoryBudget
    }

    package func acquire(
        _ preparation: EventJournalIngressPreparation
    ) -> EventJournalPreparedHandle? {
        let charge = Self.retainedByteCharge(for: preparation)
        guard let liveMemoryLease = liveMemoryBudget.tryAcquire(
            bytes: charge,
            owner: .journalPrepared
        ) else { return nil }
        lock.lock()
        guard retainedCount + compactReceiptCount < maximumCount,
              charge <= maximumBytes - min(retainedBytes, maximumBytes) else {
            lock.unlock()
            return nil
        }
        retainedCount += 1
        retainedBytes += charge
        lock.unlock()
        return EventJournalPreparedHandle(
            preparation: preparation,
            retainedByteCharge: charge,
            budget: self,
            liveMemoryLease: liveMemoryLease
        )
    }

    /// Adopt credit acquired before sanitizer/JSON allocation. Production uses
    /// this path so preparation can only run while its worst-case workspace is
    /// already inside the process-wide envelope. Adoption only shrinks credit;
    /// it can never jump ahead of FIFO budget waiters by growing in place.
    package func adopt(
        _ preparation: EventJournalIngressPreparation,
        workspaceLease: EventPipelineMemoryLease
    ) -> EventJournalPreparedHandle? {
        let charge = Self.retainedByteCharge(for: preparation)
        guard workspaceLease.owner == .journalPrepared,
              charge > 0,
              charge <= workspaceLease.bytes,
              workspaceLease.resize(to: charge) else { return nil }
        lock.lock()
        guard retainedCount + compactReceiptCount < maximumCount,
              charge <= maximumBytes - min(retainedBytes, maximumBytes) else {
            lock.unlock()
            return nil
        }
        retainedCount += 1
        retainedBytes += charge
        lock.unlock()
        return EventJournalPreparedHandle(
            preparation: preparation,
            retainedByteCharge: charge,
            budget: self,
            liveMemoryLease: workspaceLease
        )
    }

    package func snapshot() -> Snapshot {
        lock.lock()
        let value = Snapshot(
            retainedCount: retainedCount,
            compactReceiptCount: compactReceiptCount,
            liveHandleCount: retainedCount + compactReceiptCount,
            retainedBytes: retainedBytes,
            maximumCount: maximumCount,
            maximumBytes: maximumBytes
        )
        lock.unlock()
        return value
    }

    /// Static local-cap check used before an async caller waits for queue
    /// ownership to drain. Process-wide credit may backpressure temporarily;
    /// a value larger than this writer's configured test/production cap can
    /// never fit and must fail explicitly instead of waiting forever.
    package func canEventuallyAdopt(
        _ preparation: EventJournalIngressPreparation
    ) -> Bool {
        let charge = Self.retainedByteCharge(for: preparation)
        return charge > 0 && charge <= maximumBytes
    }

    fileprivate func release(bytes: Int, countedAsPrepared: Bool) {
        lock.lock()
        if countedAsPrepared {
            retainedCount = max(0, retainedCount - 1)
        } else {
            compactReceiptCount = max(0, compactReceiptCount - 1)
        }
        retainedBytes = max(0, retainedBytes - bytes)
        lock.unlock()
    }

    fileprivate func resize(from oldBytes: Int, to newBytes: Int) {
        guard oldBytes != newBytes else { return }
        lock.lock()
        // `retainedCount` is the number of full Event+canonical preparations,
        // not the number of compact 256-byte receipt metadata objects. This is
        // what lets one event's compact base receipt coexist with its terminal
        // handle even at a one-record test cap.
        retainedCount = max(0, retainedCount - 1)
        compactReceiptCount += 1
        retainedBytes = max(
            0,
            retainedBytes - min(retainedBytes, max(0, oldBytes))
        )
        let addition = max(0, newBytes)
        let sum = retainedBytes.addingReportingOverflow(addition)
        retainedBytes = sum.overflow ? maximumBytes : sum.partialValue
        lock.unlock()
    }

    /// Canonical bytes coexist with the sanitized Event graph. The validator's
    /// retained estimate already includes its conservative 64-byte structural
    /// charge for every array/map element; add the canonical Data once plus a
    /// fixed allocator/object allowance. The typed sanitizer performs no
    /// JSON-object mirror/decode copies, so the former 3x JSON multiplier would
    /// reserve memory that production no longer allocates.
    package static func retainedByteCharge(
        for preparation: EventJournalIngressPreparation
    ) -> Int {
        let graphAndJSON = preparation.retainedByteEstimate
            .addingReportingOverflow(preparation.canonicalJSON.count)
        guard !graphAndJSON.overflow else { return Int.max }
        let withOverhead = graphAndJSON.partialValue.addingReportingOverflow(
            4_096
        )
        return withOverhead.overflow
            ? Int.max : max(4_096, withOverhead.partialValue)
    }
}
