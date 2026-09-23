import Foundation
import MacCrabCore

/// Bounds how fast the applied schema-v8 upgrade reserve may fall between two
/// consecutive successful measurements.
///
/// v1.22.2. The measured candidate is an instantaneous proof: "the family fits
/// the startup-convergence target of the proposed cap right now". On a
/// v1.21.5 -> v1.22.1 upgrade lane at ~400 events/s the post-checkpoint family
/// swung by tens of MiB between sweeps as the WAL drained and regrew, so the
/// candidate moved 69 -> 74 -> 31 -> 13 -> 37 -> 3 MiB inside five minutes and
/// the live events-family cap followed it (389 -> 394 -> 351 -> 333 -> 357 ->
/// 323 MiB) while `incremental_vacuum` had physically returned only ~16 MiB per
/// sweep. events.db still held the just-migrated legacy pages, so
/// `footprint + reserve` exceeded the shrunken cap and admission paused writes
/// (`kind=footprint_limit`, `events_storage_write_dropped_total` climbing).
///
/// The reserve exists to cover bytes that are physically present but not yet
/// returned. It may therefore fall only as far as the main database actually
/// shrank since the previous measurement, and it never rises on a successful
/// measurement: a lower cap is exactly as much pressure as the bytes it stops
/// covering, so the cap step can never outrun reclaim. The measured candidate
/// remains a floor (live legacy ownership plus the startup-convergence excess),
/// so the reserve still converges to zero once legacy rows are gone and their
/// pages have been vacuumed. Whole-file page count is used rather than the
/// DB+WAL+SHM family because WAL growth and truncation are not reclaim; the
/// sub-MiB remainder of each interval's shrink carries into the next baseline
/// so small vacuum quanta still add up.
enum LegacyEvidenceReserveReclaimPolicy {
    /// Bytes physically returned by the main database between two
    /// measurements. Growth is not negative reclaim.
    static func reclaimedBytes(
        previousMainFileBytes: Int64,
        currentMainFileBytes: Int64
    ) -> Int64 {
        let previous = max(0, previousMainFileBytes)
        let current = max(0, currentMainFileBytes)
        return previous > current ? previous - current : 0
    }

    /// The reserve this measurement may apply, in MiB.
    ///
    /// - `candidateMiB`: the unbounded measured candidate (evidence ownership,
    ///   physical and startup-convergence terms).
    /// - `baselineReserveMiB`: the reserve in force at the previous
    ///   measurement.
    /// - `maximumReserveMiB`: the configured evidence allocation; an operator's
    ///   explicit lower envelope stays authoritative and clamps the result.
    /// - `reclaimedBytes`: main-file shrink since the previous measurement.
    ///
    /// Result: `min(baseline, max(candidate, baseline - floor(reclaimed MiB)))`
    /// clamped to `[0, maximum]`.
    static func boundedReserveMiB(
        candidateMiB: Int,
        baselineReserveMiB: Int,
        maximumReserveMiB: Int,
        reclaimedBytes: Int64
    ) -> Int {
        let maximum = max(0, maximumReserveMiB)
        let candidate = min(maximum, max(0, candidateMiB))
        let baseline = min(maximum, max(0, baselineReserveMiB))
        let reclaimedMiB = Int(
            clamping: max(0, reclaimedBytes)
                / SQLitePersistentStorePolicy.bytesPerMiB
        )
        let floor = reclaimedMiB >= baseline ? 0 : baseline - reclaimedMiB
        return min(baseline, max(candidate, floor))
    }

    /// The main-file baseline for the next measurement. A shrink is credited
    /// in whole MiB, so the remainder stays in the baseline; growth resets it.
    static func nextBaselineMainFileBytes(
        previousMainFileBytes: Int64,
        currentMainFileBytes: Int64
    ) -> Int64 {
        let previous = max(0, previousMainFileBytes)
        let current = max(0, currentMainFileBytes)
        guard current < previous else { return current }
        let credited = ((previous - current)
            / SQLitePersistentStorePolicy.bytesPerMiB)
            * SQLitePersistentStorePolicy.bytesPerMiB
        return previous - credited
    }
}
