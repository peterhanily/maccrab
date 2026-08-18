import Foundation
import Testing
@testable import MacCrabCore

@Suite("Process-wide event pipeline memory envelope")
struct EventPipelineLiveMemoryBudgetTests {
    private final class CancellationBox: @unchecked Sendable {
        private let lock = NSLock()
        private var task: Task<EventPipelineMemoryLease?, Never>?

        func store(_ task: Task<EventPipelineMemoryLease?, Never>) {
            lock.lock()
            self.task = task
            lock.unlock()
        }

        func cancel() {
            lock.lock()
            let task = task
            lock.unlock()
            task?.cancel()
        }
    }

    private func waitUntil(
        _ predicate: @escaping @Sendable () -> Bool
    ) async {
        for _ in 0..<2_000 {
            if predicate() { return }
            await Task.yield()
        }
    }

    @Test("lease split, transfer, and ARC release conserve ownership")
    func leaseConservation() async throws {
        let budget = EventPipelineLiveMemoryBudget(maximumBytes: 1_024)
        var source: EventPipelineMemoryLease? = try #require(
            budget.tryAcquire(bytes: 800, owner: .eventSource)
        )
        var patch: EventPipelineMemoryLease? = try #require(
            source?.split(bytes: 300, owner: .heavyResult)
        )
        #expect(patch?.transfer(to: .deferredPatch) == true)
        var snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 800)
        #expect(snapshot.activeLeases == 2)
        #expect(snapshot.leasesConserved)
        #expect(snapshot.bytesByOwner["event_source"] == 500)
        #expect(snapshot.bytesByOwner["deferred_patch"] == 300)

        patch = nil
        source = nil
        snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 0)
        #expect(snapshot.activeLeases == 0)
        #expect(snapshot.leasesConserved)
        #expect(snapshot.withinCapacity)
    }

    @Test("async waits are benign while nonblocking and hard limits are explicit")
    func backpressureCountersAndCancellation() async throws {
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 10,
            maximumWaiters: 1
        )
        var blocker: EventPipelineMemoryLease? = try #require(
            budget.tryAcquire(bytes: 10, owner: .eventSource)
        )
        let waiting = Task {
            await budget.acquire(bytes: 10, owner: .eventSource)
        }
        await waitUntil { budget.snapshot().waitingAcquisitions == 1 }

        let rejectedAtWaiterLimit = await budget.acquire(
            bytes: 1,
            owner: .heavyResult
        )
        #expect(rejectedAtWaiterLimit == nil)
        #expect(budget.tryAcquire(bytes: 1, owner: .heavyResult) == nil)
        #expect(budget.tryAcquire(bytes: 11, owner: .heavyResult) == nil)

        // Release and cancellation deliberately race. If release assigned the
        // lease first, acquire's post-continuation cancellation check must drop
        // that credit before returning to this caller.
        blocker = nil
        waiting.cancel()
        #expect(await waiting.value == nil)
        await waitUntil { budget.snapshot().currentBytes == 0 }

        let snapshot = budget.snapshot()
        #expect(snapshot.waitsTotal == 1)
        #expect(snapshot.waiterLimitSaturationsTotal == 1)
        #expect(snapshot.nonblockingRejectionsTotal == 1)
        #expect(snapshot.oversizedRequestsTotal == 1)
        #expect(snapshot.cancelledWaiterTotal == 1)
        #expect(snapshot.waitingAcquisitions == 0)
        #expect(snapshot.leasesConserved)
    }

    @Test("assigned-before-resume cancellation releases credit and is counted")
    func assignedWaiterCancellation() async throws {
        let budget = EventPipelineLiveMemoryBudget(maximumBytes: 10)
        let cancellation = CancellationBox()
        budget.setWaiterAssignedHookForTesting { cancellation.cancel() }
        var blocker: EventPipelineMemoryLease? = try #require(
            budget.tryAcquire(bytes: 10, owner: .eventSource)
        )
        let waiting = Task {
            await budget.acquire(bytes: 10, owner: .eventSource)
        }
        cancellation.store(waiting)
        await waitUntil { budget.snapshot().waitingAcquisitions == 1 }

        blocker = nil
        #expect(await waiting.value == nil)
        await waitUntil { budget.snapshot().currentBytes == 0 }
        let snapshot = budget.snapshot()
        #expect(snapshot.cancelledWaiterTotal == 1)
        #expect(snapshot.waitingAcquisitions == 0)
        #expect(snapshot.activeLeases == 0)
        #expect(snapshot.leasesConserved)
    }

    @Test("noncritical requests above their owner ceiling fail immediately")
    func impossibleNoncriticalRequestIsOversized() async throws {
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 96,
            forwardProgressReserveBytes: 36
        )
        #expect(await budget.acquire(bytes: 61, owner: .eventSource) == nil)
        #expect(budget.tryAcquire(bytes: 61, owner: .heavyResult) == nil)
        var source: EventPipelineMemoryLease? = try #require(
            await budget.acquire(bytes: 60, owner: .eventSource)
        )
        #expect(source?.resize(to: 61) == false)

        var snapshot = budget.snapshot()
        #expect(snapshot.oversizedRequestsTotal == 3)
        #expect(snapshot.waitsTotal == 0)
        #expect(snapshot.waitingAcquisitions == 0)
        #expect(snapshot.currentBytes == 60)
        source = nil
        snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 0)
        #expect(snapshot.leasesConserved)
    }

    @Test("max source plus second-lane residual and receipts preserve J/S progress")
    func simultaneousLaneForwardProgress() async throws {
        let mib = 1_024 * 1_024
        let journalBytes = EventJournalAdmissionValidator
            .maximumPreparationWorkspaceBytes
        let storageBytes = EventJournalCodec.maximumWorkspaceBytes
        let receiptBytes = EventJournalPreparedOwnershipBudget
            .productionCompactReceiptReserveBytes
        #expect(journalBytes + storageBytes == 48 * mib)
        let forwardReserve = journalBytes + storageBytes + receiptBytes
        let noncriticalBytes = 96 * mib - forwardReserve
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 96 * mib,
            maximumWaiters: 8,
            forwardProgressReserveBytes: forwardReserve,
            eventStoreWorkspaceReserveBytes: storageBytes,
            compactReceiptReserveBytes: receiptBytes
        )
        var firstSource: EventPipelineMemoryLease? = try #require(
            await budget.acquire(bytes: 24 * mib, owner: .eventSource)
        )
        var secondSource: EventPipelineMemoryLease? = try #require(
            await budget.acquire(
                bytes: noncriticalBytes - 24 * mib,
                owner: .eventSource
            )
        )
        var receipts: EventPipelineMemoryLease? = try #require(
            await budget.acquire(
                bytes: receiptBytes,
                owner: .journalPrepared
            )
        )
        #expect(budget.tryAcquire(bytes: 1, owner: .heavyResult) == nil)

        // A noncritical H waiter arrives first but cannot consume reserved J+S
        // headroom. The oldest base boundary and its downstream EventStore
        // workspace must bypass it and advance.
        let queuedHeavy = Task {
            let lease = await budget.acquire(bytes: 1, owner: .heavyResult)
            #expect(lease != nil)
        }
        await waitUntil { budget.snapshot().waitingAcquisitions == 1 }

        var storage: EventPipelineMemoryLease? = try #require(
            budget.tryAcquire(
                bytes: storageBytes,
                owner: .eventStoreWorkspace
            )
        )
        var journal: EventPipelineMemoryLease? = try #require(
            await budget.acquire(bytes: journalBytes, owner: .journalPrepared)
        )
        var snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 96 * mib)
        #expect(snapshot.bytesByOwner["event_source"] == noncriticalBytes)
        #expect(snapshot.bytesByOwner["journal_prepared"]
            == journalBytes + receiptBytes)
        #expect(snapshot.bytesByOwner["event_store_workspace"] == storageBytes)
        #expect(snapshot.forwardProgressReserveBytes == forwardReserve)
        #expect(snapshot.eventStoreWorkspaceReserveBytes == storageBytes)
        #expect(snapshot.compactReceiptReserveBytes == receiptBytes)
        #expect(snapshot.waitingAcquisitions == 1)
        #expect(snapshot.withinCapacity)
        #expect(snapshot.leasesConserved)

        storage = nil
        journal = nil
        receipts = nil
        firstSource = nil
        await queuedHeavy.value
        secondSource = nil
        snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 0)
        #expect(snapshot.activeLeases == 0)
        #expect(snapshot.leasesConserved)
    }

    @Test("S workspace bypasses an older blocked J waiter")
    func storageWorkspaceIsDownstreamReleaseValve() async throws {
        let mib = 1_024 * 1_024
        let journalBytes = EventJournalAdmissionValidator
            .maximumPreparationWorkspaceBytes
        let storageBytes = EventJournalCodec.maximumWorkspaceBytes
        let receiptBytes = EventJournalPreparedOwnershipBudget
            .productionCompactReceiptReserveBytes
        let forwardReserve = journalBytes + storageBytes + receiptBytes
        let noncriticalBytes = 96 * mib - forwardReserve
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 96 * mib,
            maximumWaiters: 8,
            forwardProgressReserveBytes: forwardReserve,
            eventStoreWorkspaceReserveBytes: storageBytes,
            compactReceiptReserveBytes: receiptBytes
        )
        var sources: EventPipelineMemoryLease? = try #require(
            await budget.acquire(
                bytes: noncriticalBytes,
                owner: .eventSource
            )
        )
        var receipts: EventPipelineMemoryLease? = try #require(
            await budget.acquire(
                bytes: receiptBytes,
                owner: .journalPrepared
            )
        )
        var firstJournal: EventPipelineMemoryLease? = try #require(
            await budget.acquire(
                bytes: journalBytes,
                owner: .journalPrepared
            )
        )
        let blockedJournal = Task {
            let lease = await budget.acquire(
                bytes: journalBytes,
                owner: .journalPrepared
            )
            #expect(lease != nil)
        }
        await waitUntil { budget.snapshot().waitingAcquisitions == 1 }

        var storage: EventPipelineMemoryLease? = try #require(
            budget.tryAcquire(
                bytes: storageBytes,
                owner: .eventStoreWorkspace
            )
        )
        var snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 96 * mib)
        #expect(snapshot.waitingAcquisitions == 1)
        #expect(snapshot.bytesByOwner["event_store_workspace"] == storageBytes)

        storage = nil
        firstJournal = nil
        await blockedJournal.value
        receipts = nil
        sources = nil
        snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 0)
        #expect(snapshot.activeLeases == 0)
        #expect(snapshot.leasesConserved)
    }

    @Test("growth and critical relabeling cannot consume reserved headroom")
    func growthHonorsForwardProgressReserve() async throws {
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 100,
            forwardProgressReserveBytes: 40
        )
        var source: EventPipelineMemoryLease? = try #require(
            budget.tryAcquire(bytes: 60, owner: .eventSource)
        )
        #expect(source?.resize(to: 61) == false)

        var journal: EventPipelineMemoryLease? = try #require(
            await budget.acquire(bytes: 40, owner: .journalPrepared)
        )
        #expect(journal?.transfer(to: .heavyResult) == false)
        #expect(journal?.split(bytes: 1, owner: .deferredPatch) == nil)
        let saturated = budget.snapshot()
        #expect(saturated.currentBytes == 100)
        #expect(saturated.bytesByOwner["event_source"] == 60)
        #expect(saturated.bytesByOwner["journal_prepared"] == 40)
        #expect(saturated.withinCapacity)

        source = nil
        journal = nil
        let drained = budget.snapshot()
        #expect(drained.currentBytes == 0)
        #expect(drained.leasesConserved)
    }

    @Test("terminal heavy-result handoff survives journal use of reserved headroom")
    func inClassTransferSurvivesCriticalPressure() async throws {
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 100,
            forwardProgressReserveBytes: 40
        )
        var result: EventPipelineMemoryLease? = try #require(
            budget.tryAcquire(bytes: 10, owner: .heavyResult)
        )
        var journal: EventPipelineMemoryLease? = try #require(
            await budget.acquire(bytes: 70, owner: .journalPrepared)
        )
        var snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 80)
        #expect(snapshot.currentBytes > 60,
                "critical work must reproduce total pressure above the noncritical ceiling")

        #expect(result?.transfer(to: .deferredPatch) == true,
                "an already-owned terminal result must not be stranded by a zero-byte handoff")
        snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 80)
        #expect(snapshot.bytesByOwner["deferred_patch"] == 10)
        #expect(snapshot.bytesByOwner["heavy_result"] == 0)
        #expect(snapshot.nonblockingRejectionsTotal == 0)
        #expect(snapshot.withinCapacity)
        #expect(snapshot.leasesConserved)

        result = nil
        journal = nil
        snapshot = budget.snapshot()
        #expect(snapshot.currentBytes == 0)
        #expect(snapshot.activeLeases == 0)
        #expect(snapshot.leasesConserved)
    }

    @Test("derived tasks inherit one source charge until their Event capture exits")
    func taskLocalSourceOwnership() async throws {
        let budget = EventPipelineLiveMemoryBudget(maximumBytes: 1_024)
        var source: EventPipelineMemoryLease? = try #require(
            budget.tryAcquire(bytes: 700, owner: .eventSource)
        )
        var child: Task<Int, Never>?
        EventJournalAdmissionContext.$sourceMemoryLease.withValue(source) {
            child = Task {
                try? await Task.sleep(for: .milliseconds(20))
                return EventJournalAdmissionContext.sourceMemoryLease?.bytes
                    ?? 0
            }
        }
        source = nil
        #expect(budget.snapshot().currentBytes == 700,
                "the child TaskLocal must retain the shared source lease")
        #expect(await child?.value == 700)
        child = nil
        await waitUntil { budget.snapshot().currentBytes == 0 }
        #expect(budget.snapshot().leasesConserved)
    }

    @Test("deferred replay children retain applied patch credits")
    func taskLocalPatchOwnership() async throws {
        let budget = EventPipelineLiveMemoryBudget(maximumBytes: 1_024)
        var patch: EventPipelineMemoryLease? = try #require(
            budget.tryAcquire(bytes: 300, owner: .deferredPatch)
        )
        var child: Task<Int, Never>?
        EventJournalAdmissionContext.$deferredPatchMemoryLeases.withValue(
            [try #require(patch)]
        ) {
            child = Task {
                try? await Task.sleep(for: .milliseconds(20))
                return EventJournalAdmissionContext
                    .deferredPatchMemoryLeases.reduce(0) { $0 + $1.bytes }
            }
        }
        patch = nil
        #expect(budget.snapshot().currentBytes == 300)
        #expect(await child?.value == 300)
        child = nil
        await waitUntil { budget.snapshot().currentBytes == 0 }
        #expect(budget.snapshot().leasesConserved)
    }
}

// MARK: - rc.33 regression: drain-side priority inversion
//
// EventStore acquires exclusively through `tryAcquire` (7 call sites, zero
// `acquire`), so it can never become a FIFO waiter. When the waiter-fairness
// gate applied to it unconditionally, a single parked waiter locked out the only
// actor able to finish a write and release the credit that waiter needed. An
// installed host sat at events_storage_write_persisted_total = 0 with 36 MiB of
// its 96 MiB envelope free and 46 non-blocking rejections recorded.
@Suite("rc.33 drain-side forward progress", .serialized)
struct DrainSidePriorityInversionTests {

    @Test("A parked drain-side waiter cannot block the drain side out of free capacity")
    func drainSideProceedsDespiteParkedWaiter() async {
        let budget = EventPipelineLiveMemoryBudget
            .isolatedProductionEquivalentForTesting()
        let maximum = budget.snapshot().maximumBytes

        // The waiter MUST be a drain-side owner. The old fairness gate only
        // blocked `.journalPrepared` behind `.eventStoreWorkspace` /
        // `.journalPrepared` waiters, so parking a source-side waiter would let
        // this test pass with or without the fix and prove nothing.
        let held = budget.tryAcquire(bytes: maximum / 2, owner: .journalPrepared)
        #expect(held != nil, "precondition: first drain reservation should fit")

        // Parks: the remaining envelope cannot satisfy another half.
        let parked = Task {
            await budget.acquire(bytes: maximum / 2, owner: .journalPrepared)
        }
        for _ in 0..<2_000 where budget.snapshot().waitingAcquisitions == 0 {
            await Task.yield()
        }
        #expect(budget.snapshot().waitingAcquisitions >= 1)

        // A SMALL drain-side request that the envelope can still satisfy. This is
        // the shape of the live failure: 36 MiB free, one waiter parked, and
        // EventStore refused 46 times. EventStore never calls the blocking
        // `acquire`, so being refused here is terminal — it is the only actor
        // that can finish a write and release the credit the waiter needs.
        let progress = budget.tryAcquire(bytes: 1_024 * 1_024, owner: .journalPrepared)
        #expect(
            progress != nil,
            "drain side refused with free capacity while a drain waiter was parked — priority inversion"
        )

        parked.cancel()
        _ = await parked.value
    }

    @Test("Source-side owners still queue behind parked waiters")
    func sourceSideStillRespectsFairness() async {
        let budget = EventPipelineLiveMemoryBudget
            .isolatedProductionEquivalentForTesting()
        let snapshot = budget.snapshot()

        let sourceCeiling = snapshot.maximumBytes
            - snapshot.forwardProgressReserveBytes
        // Deliberately leave headroom. Filling to the exact ceiling would make
        // the assertion below pass because of byte exhaustion rather than
        // fairness, which would not test what it claims to.
        let headroom = 4 * 1_024 * 1_024
        let hog = budget.tryAcquire(
            bytes: sourceCeiling - headroom,
            owner: .eventSource
        )
        #expect(hog != nil)

        // Parks: it wants more than the headroom that remains.
        let parked = Task {
            await budget.acquire(bytes: headroom * 2, owner: .eventSource)
        }
        for _ in 0..<2_000 where budget.snapshot().waitingAcquisitions == 0 {
            await Task.yield()
        }
        #expect(budget.snapshot().waitingAcquisitions >= 1)

        // 4 KiB fits in the remaining headroom, so ONLY the fairness gate can
        // refuse it. The exemption is deliberately narrow: it must not hand
        // source-side owners a queue-jumping path, or FIFO is gone.
        #expect(
            budget.tryAcquire(bytes: 4_096, owner: .eventSource) == nil,
            "source side jumped the queue — fairness exemption is too broad"
        )

        parked.cancel()
        _ = await parked.value
    }
}
