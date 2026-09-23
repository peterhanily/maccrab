import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

// v1.22.2: the applied legacy-evidence reserve may fall only as fast as the
// main database physically shrinks. On a v1.21.5 -> v1.22.1 upgrade lane the
// instantaneous candidate moved 69 -> 74 -> 31 -> 13 -> 37 -> 3 MiB in five
// minutes while incremental_vacuum returned 4090 pages (~16 MiB) per sweep, and
// the events-family cap followed the candidate straight into a write pause.
@Suite("Legacy evidence reserve reclaim bound")
struct LegacyEvidenceReserveReclaimPolicyTests {
    private let mib = SQLitePersistentStorePolicy.bytesPerMiB
    /// One observed sweep: `incremental_vacuum reclaimed 4090 pages`.
    private let sweepReclaim: Int64 = 4_090 * 4_096

    @Test("the observed upgrade lane can no longer outrun reclaim")
    func observedLaneReplay() {
        // Old behaviour applied every candidate verbatim: 69, 74, 31, 13, 37, 3.
        let candidates = [74, 31, 13, 37, 3]
        var reserve = 69
        var baseline: Int64 = 300 * mib
        var mainFile = baseline
        var applied: [Int] = []
        for (index, candidate) in candidates.enumerated() {
            // The first scheduled sweep measured before any vacuum; every
            // later sweep had returned one quantum.
            if index > 0 { mainFile -= sweepReclaim }
            let reclaimed = LegacyEvidenceReserveReclaimPolicy.reclaimedBytes(
                previousMainFileBytes: baseline,
                currentMainFileBytes: mainFile
            )
            let next = LegacyEvidenceReserveReclaimPolicy.boundedReserveMiB(
                candidateMiB: candidate,
                baselineReserveMiB: reserve,
                maximumReserveMiB: 100,
                reclaimedBytes: reclaimed
            )
            #expect(next <= reserve, "a successful measurement never raises the reserve")
            #expect(Int64(reserve - next) * mib <= reclaimed, "a cap step never exceeds the bytes reclaimed")
            #expect(next >= min(candidate, reserve), "the measured candidate remains a floor up to the baseline")
            baseline = LegacyEvidenceReserveReclaimPolicy
                .nextBaselineMainFileBytes(
                    previousMainFileBytes: baseline,
                    currentMainFileBytes: mainFile
                )
            reserve = next
            applied.append(next)
        }
        // 15.97 MiB per sweep credits 15 whole MiB first, then the carried
        // remainder makes the following quanta worth 16 MiB each.
        #expect(applied == [69, 54, 38, 37, 21])
        // Live cap on the lane (320 MiB steady): 389, 374, 358, 357, 341 MiB
        // instead of 394, 351, 333, 357, 323 MiB.
        #expect(applied.map { 320 + $0 } == [389, 374, 358, 357, 341])
    }

    @Test("no reclaim means no shrink, whatever the candidate says")
    func zeroReclaimHolds() {
        #expect(LegacyEvidenceReserveReclaimPolicy.boundedReserveMiB(
            candidateMiB: 0,
            baselineReserveMiB: 69,
            maximumReserveMiB: 100,
            reclaimedBytes: 0
        ) == 69)
        // Sub-MiB shrink rounds down to nothing.
        #expect(LegacyEvidenceReserveReclaimPolicy.boundedReserveMiB(
            candidateMiB: 0,
            baselineReserveMiB: 69,
            maximumReserveMiB: 100,
            reclaimedBytes: mib - 1
        ) == 69)
        #expect(LegacyEvidenceReserveReclaimPolicy.reclaimedBytes(
            previousMainFileBytes: 100 * mib,
            currentMainFileBytes: 140 * mib
        ) == 0)
    }

    @Test("a candidate above the baseline never raises the reserve")
    func monotone() {
        #expect(LegacyEvidenceReserveReclaimPolicy.boundedReserveMiB(
            candidateMiB: 74,
            baselineReserveMiB: 69,
            maximumReserveMiB: 100,
            reclaimedBytes: 50 * mib
        ) == 69)
    }

    @Test("enough reclaim lets the reserve reach the candidate, including zero")
    func convergesToCandidate() {
        #expect(LegacyEvidenceReserveReclaimPolicy.boundedReserveMiB(
            candidateMiB: 0,
            baselineReserveMiB: 21,
            maximumReserveMiB: 100,
            reclaimedBytes: 21 * mib
        ) == 0)
        #expect(LegacyEvidenceReserveReclaimPolicy.boundedReserveMiB(
            candidateMiB: 0,
            baselineReserveMiB: 21,
            maximumReserveMiB: 100,
            reclaimedBytes: Int64.max
        ) == 0)
        #expect(LegacyEvidenceReserveReclaimPolicy.boundedReserveMiB(
            candidateMiB: 12,
            baselineReserveMiB: 21,
            maximumReserveMiB: 100,
            reclaimedBytes: 21 * mib
        ) == 12)
    }

    @Test("an explicit lower evidence allocation stays authoritative")
    func maximumClamps() {
        #expect(LegacyEvidenceReserveReclaimPolicy.boundedReserveMiB(
            candidateMiB: 60,
            baselineReserveMiB: 69,
            maximumReserveMiB: 20,
            reclaimedBytes: 0
        ) == 20)
        #expect(LegacyEvidenceReserveReclaimPolicy.boundedReserveMiB(
            candidateMiB: -5,
            baselineReserveMiB: -5,
            maximumReserveMiB: -1,
            reclaimedBytes: -1
        ) == 0)
    }

    @Test("the sub-MiB remainder of a shrink carries into the next baseline")
    func remainderCarries() {
        let previous: Int64 = 300 * mib
        let current = previous - sweepReclaim
        let next = LegacyEvidenceReserveReclaimPolicy.nextBaselineMainFileBytes(
            previousMainFileBytes: previous,
            currentMainFileBytes: current
        )
        #expect(next == previous - 15 * mib)
        #expect(next >= current)
        // Growth resets the baseline to the current size.
        #expect(LegacyEvidenceReserveReclaimPolicy.nextBaselineMainFileBytes(
            previousMainFileBytes: previous,
            currentMainFileBytes: previous + 1
        ) == previous + 1)
        #expect(LegacyEvidenceReserveReclaimPolicy.nextBaselineMainFileBytes(
            previousMainFileBytes: previous,
            currentMainFileBytes: previous
        ) == previous)
    }
}

@Suite("Legacy evidence transition budget reclaim bound")
struct LegacyEvidenceTransitionBudgetReclaimTests {
    private let mib = SQLitePersistentStorePolicy.bytesPerMiB
    private let pageSize: Int64 = 4_096
    private let bootPages: Int64 = 76_800 // 300 MiB

    private func laneStorage() -> DaemonConfig.StorageConfig {
        var storage = DaemonConfig.StorageConfig().clampedToSafeFloors()
        storage.eventsMaxSizeMB = 420 // 320 MiB steady family, as on the lane
        return storage
    }

    /// Family stays comfortably inside every startup target so the candidate
    /// is driven by legacy-evidence ownership alone; the page count carries
    /// the physical shrink.
    private func measurement(
        chargedMiB: Int64,
        pageCount: Int64,
        checkpointDrained: Bool = true
    ) -> LegacyAlertEvidenceTransitionMeasurement {
        LegacyAlertEvidenceTransitionMeasurement(
            evidence: AlertEvidenceBudgetSnapshot(
                rowCount: chargedMiB == 0 ? 0 : 1_000,
                logicalBytes: chargedMiB * mib,
                allocatedBytes: chargedMiB * mib,
                chargedBytes: chargedMiB * mib,
                maxBytes: 100 * mib
            ),
            familyFootprintBytes: 200 * mib,
            walCheckpointDrained: checkpointDrained,
            pageSizeBytes: pageSize,
            pageCount: pageCount,
            freelistCount: 0
        )
    }

    private func boot(_ budget: LegacyEvidenceTransitionBudget)
        -> LegacyEvidenceTransitionMeasurementTicket {
        let ticket = budget.measurementTicket()
        let measured = budget.update(
            measurement: measurement(chargedMiB: 69, pageCount: bootPages),
            ticket: ticket
        )
        #expect(measured.pendingReserveMiB == 69)
        #expect(measured.pendingReserveFitsHardBoundary == true)
        let committed = budget.commitPendingReserve(69, ticket: ticket)
        #expect(committed.appliedReserveMiB == 69)
        #expect(committed.reclaimBaselineReserveMiB == 69)
        #expect(committed.reclaimBaselineMainFileBytes == bootPages * pageSize)
        return ticket
    }

    @Test("sweeps shrink the reserve only as the main file shrinks, then converge to zero")
    func sweepSequence() {
        let budget = LegacyEvidenceTransitionBudget(storageConfig: laneStorage())
        let ticket = boot(budget)

        // Legacy rows aged out (candidate 31) but nothing was vacuumed yet.
        let held = budget.update(
            measurement: measurement(chargedMiB: 31, pageCount: bootPages),
            ticket: ticket
        )
        #expect(held.appliedReserveMiB == 69)
        #expect(held.pendingReserveMiB == nil)
        #expect(held.measuredCandidateMiB == 31)
        #expect(held.lastReclaimedBytes == 0)

        // One vacuum quantum (4090 pages = 15.97 MiB) credits 15 MiB.
        let firstQuantum = budget.update(
            measurement: measurement(chargedMiB: 13, pageCount: bootPages - 4_090),
            ticket: ticket
        )
        #expect(firstQuantum.pendingReserveMiB == 54)
        #expect(firstQuantum.pendingReserveFitsHardBoundary == true)
        #expect(firstQuantum.lastReclaimedBytes == 4_090 * pageSize)
        #expect(firstQuantum.reclaimBaselineMainFileBytes
            == bootPages * pageSize - 15 * mib)
        let applied54 = budget.commitPendingReserve(54, ticket: ticket)
        #expect(applied54.appliedReserveMiB == 54)
        #expect(applied54.reclaimBaselineReserveMiB == 54)

        // A failed probe still grows to the full allowance (fail-safe), but it
        // does not become the reclaim baseline.
        let failed = budget.update(measurement: nil, ticket: ticket)
        #expect(failed.pendingReserveMiB == 100)
        #expect(failed.pendingReserveFitsHardBoundary == true)
        let grown = budget.commitPendingReserve(100, ticket: ticket)
        #expect(grown.appliedReserveMiB == 100)
        #expect(grown.reclaimBaselineReserveMiB == 54)

        // Legacy rows are gone (candidate 0); a second quantum plus the carried
        // remainder is worth 16 MiB against the measured 54, not the grown 100.
        let secondQuantum = budget.update(
            measurement: measurement(chargedMiB: 0, pageCount: bootPages - 8_180),
            ticket: ticket
        )
        #expect(secondQuantum.measuredCandidateMiB == 0)
        #expect(secondQuantum.pendingReserveMiB == 38)
        #expect(secondQuantum.pendingReserveFitsHardBoundary == true)
        #expect(secondQuantum.lastReclaimedBytes == 2 * 4_090 * pageSize - 15 * mib)
        #expect(budget.commitPendingReserve(38, ticket: ticket).appliedReserveMiB == 38)

        // No physical change: held, even though the candidate is zero.
        let unchanged = budget.update(
            measurement: measurement(chargedMiB: 0, pageCount: bootPages - 8_180),
            ticket: ticket
        )
        #expect(unchanged.appliedReserveMiB == 38)
        #expect(unchanged.pendingReserveMiB == nil)
        #expect(unchanged.lastReclaimedBytes ?? 0 < mib)

        // Growth is not negative reclaim and simply resets the baseline.
        let grownFile = budget.update(
            measurement: measurement(chargedMiB: 0, pageCount: bootPages + 2_000),
            ticket: ticket
        )
        #expect(grownFile.appliedReserveMiB == 38)
        #expect(grownFile.pendingReserveMiB == nil)
        #expect(grownFile.lastReclaimedBytes == 0)
        #expect(grownFile.reclaimBaselineMainFileBytes
            == (bootPages + 2_000) * pageSize)

        // Once the remaining 38 MiB have been returned the reserve reaches
        // zero and the live cap is the steady 320 MiB family again.
        let reclaimedPages = 38 * mib / pageSize
        let converged = budget.update(
            measurement: measurement(
                chargedMiB: 0,
                pageCount: bootPages + 2_000 - reclaimedPages
            ),
            ticket: ticket
        )
        #expect(converged.pendingReserveMiB == 0)
        #expect(converged.pendingReserveFitsHardBoundary == true)
        #expect(converged.lastReclaimedBytes == 38 * mib)
        let zero = budget.commitPendingReserve(0, ticket: ticket)
        #expect(zero.appliedReserveMiB == 0)
        #expect(zero.reclaimBaselineReserveMiB == 0)
        #expect(budget.storageConfig().effectiveEventsFamilyMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB: zero.appliedReserveMiB
        ) == 320)
    }

    @Test("a pinned WAL reader keeps the bounded candidate pending")
    func pinnedReaderKeepsBoundedCandidatePending() {
        let budget = LegacyEvidenceTransitionBudget(storageConfig: laneStorage())
        let ticket = boot(budget)
        let pinned = budget.update(
            measurement: measurement(
                chargedMiB: 0,
                pageCount: bootPages - 4_090,
                checkpointDrained: false
            ),
            ticket: ticket
        )
        #expect(pinned.appliedReserveMiB == 69)
        #expect(pinned.pendingReserveMiB == 54)
        #expect(pinned.pendingReserveFitsHardBoundary == false)
        #expect(budget.commitPendingReserve(54, ticket: ticket).appliedReserveMiB == 69)
    }

    @Test("a config reload keeps the reclaim baseline and never re-grows the reserve")
    func reloadKeepsBaseline() {
        let budget = LegacyEvidenceTransitionBudget(storageConfig: laneStorage())
        _ = boot(budget)

        // Operator lowers the evidence allocation to its 50 MiB floor: the
        // explicit envelope wins immediately, exactly as before.
        var lowered = laneStorage()
        lowered.evidenceMaxSizeMB = 50
        let loweredTicket = budget.installStorageConfig(lowered)
        let clamped = budget.update(
            measurement: measurement(chargedMiB: 69, pageCount: bootPages),
            ticket: loweredTicket
        )
        #expect(clamped.reclaimBaselineReserveMiB == 69)
        #expect(clamped.pendingReserveMiB == 50)
        #expect(clamped.pendingReserveFitsHardBoundary == true)
        let applied50 = budget.commitPendingReserve(50, ticket: loweredTicket)
        #expect(applied50.appliedReserveMiB == 50)
        #expect(applied50.reclaimBaselineReserveMiB == 50)

        // Raising it again publishes the fail-safe growth candidate, but the
        // next measurement resumes from the measured 50 MiB: a reload cannot
        // re-derive a larger reserve from an instantaneous footprint.
        let raisedTicket = budget.installStorageConfig(laneStorage())
        #expect(budget.snapshot().pendingReserveMiB == 100)
        let remeasured = budget.update(
            measurement: measurement(chargedMiB: 5, pageCount: bootPages),
            ticket: raisedTicket
        )
        #expect(remeasured.appliedReserveMiB == 50)
        #expect(remeasured.pendingReserveMiB == nil)
        #expect(remeasured.measuredCandidateMiB == 5)
        #expect(remeasured.reclaimBaselineMainFileBytes == bootPages * pageSize)
    }
}
