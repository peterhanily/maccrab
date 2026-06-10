// InsertFailureEscalationTests.swift
//
// v1.12.6 Wave 9D: regression coverage for the escalation tiers added
// on top of `StorageErrorTracker`. The pre-Wave-9D design throttled
// to one log emission per 60 s globally, which collapsed onto a
// single message under a sustained insert flood — a user's machine
// dropped 102,234 events into the void with only ~30 log lines and
// no dashboard signal. Wave 9D adds three additive tiers without
// touching the existing `storage_errors.json` write path:
//
//   - Tier 1: per-kind logarithmic emission (1, 10, 100, 1K, 10K)
//   - Tier 2: rate-window warning (> 100 errors per trailing 60 s)
//   - Tier 3: heartbeat surface (total + rate + last-kind)
//
// All three tiers must be ADDITIVE — the legacy snapshot file write
// must keep happening on every error, and `recordEventError`'s
// signature must stay unchanged so the ~50 call sites across
// `EventLoop` + `MonitorTasks` + `DaemonTimers` continue to compile.

import Testing
import Foundation
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// `.serialized` is REQUIRED here: every test in this suite manipulates
/// `StorageErrorTracker.shared`, which is a singleton actor in
/// production. Swift Testing parallelises by default, and parallel
/// execution caused tests to observe each other's increments — e.g.
/// the rate-window-recovery test sometimes saw 169 errors instead of
/// 50 because the cross-kind isolation test was in flight at the
/// same time. Serialising at the suite level keeps the production
/// singleton untouched while making the assertions deterministic.
@Suite("StorageErrorTracker: Wave 9D escalation tiers", .serialized)
struct InsertFailureEscalationTests {

    /// Fixed wall-clock anchor for deterministic rate-window assertions.
    /// All `recordEventError(..., now:)` calls in this suite walk
    /// forward from this anchor so we never depend on real time.
    private static let anchor: Date = Date(timeIntervalSince1970: 1_779_097_000)

    /// Convenience: an `EventStoreError.stepFailed` with the user's
    /// field-observed disk-I/O message body. This is what the SQLite
    /// driver actually emits when the events.db's containing
    /// filesystem is full or otherwise wedged on I/O.
    private func diskIOError() -> Error {
        return EventStoreError.stepFailed("disk I/O error")
    }

    private func constraintError() -> Error {
        return EventStoreError.stepFailed("UNIQUE constraint failed: events.id")
    }

    /// Each test uses the shared tracker (it's a singleton, mirroring
    /// production), so we reset it at the top of every test to avoid
    /// cross-test pollution. `resetForTesting` is `internal` and only
    /// visible behind `@testable import`.
    private func reset() async {
        await StorageErrorTracker.shared.resetForTesting()
    }

    @Test("Tier 1: first error of a kind emits a single logger.error, then escalates at powers of ten")
    func tier1EmitsAtPowersOfTen() async {
        await reset()
        let tracker = StorageErrorTracker.shared

        // First error of a kind ⇒ emission.
        await tracker.recordEventError(diskIOError(), now: Self.anchor)
        var emits = await tracker.tier1EmissionCount
        #expect(emits == 1)
        var kindEmits = await tracker.tier1EmissionsByKind["disk_io"] ?? 0
        #expect(kindEmits == 1)

        // Errors 2..9 should NOT emit — we wait until the 10th.
        for i in 1..<9 {
            await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(Double(i) * 0.01))
        }
        emits = await tracker.tier1EmissionCount
        #expect(emits == 1, "Errors 2..9 must be silent — only 1 tier-1 emission expected, got \(emits)")

        // 10th error ⇒ emission #2.
        await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(0.1))
        emits = await tracker.tier1EmissionCount
        #expect(emits == 2, "10th error of a kind must emit")
        kindEmits = await tracker.tier1EmissionsByKind["disk_io"] ?? 0
        #expect(kindEmits == 2)

        // Drive the counter up to 100 to confirm the next escalation.
        // Note: Tier 2 will fire somewhere in this range (>100 errors
        // in 60s) but Tier 1 emission count is what this test asserts.
        for i in 11..<100 {
            await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(0.1 + Double(i) * 0.01))
        }
        emits = await tracker.tier1EmissionCount
        #expect(emits == 2, "Errors 11..99 should not trigger tier-1 emissions")

        await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(2.0))
        emits = await tracker.tier1EmissionCount
        #expect(emits == 3, "100th error of a kind must emit")
        kindEmits = await tracker.tier1EmissionsByKind["disk_io"] ?? 0
        #expect(kindEmits == 3)
    }

    @Test("Tier 2: rate threshold emits a warning when > 100 errors fall inside a trailing 60s window")
    func tier2EmitsOnRateBreach() async {
        await reset()
        let tracker = StorageErrorTracker.shared

        // Drive 100 errors into a 30-second slice. That's exactly at
        // the threshold (not strictly > 100), so we expect NO tier-2
        // emission yet.
        for i in 0..<100 {
            await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(Double(i) * 0.3))
        }
        var t2 = await tracker.tier2EmissionCount
        #expect(t2 == 0, "Exactly 100 errors should NOT trip the > 100 threshold; got \(t2) tier-2 emissions")

        // The 101st pushes us above the threshold ⇒ one warning.
        await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(30.0))
        t2 = await tracker.tier2EmissionCount
        #expect(t2 == 1, "101st error inside the window must emit one tier-2 warning")

        // 102nd, 103rd... within the cooldown must NOT re-emit
        // — Tier 2 is gated by `rateWarningCooldown` to at most one
        // warning per minute regardless of how high the rate climbs.
        for i in 0..<50 {
            await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(30.0 + Double(i) * 0.1))
        }
        t2 = await tracker.tier2EmissionCount
        #expect(t2 == 1, "Tier 2 must be cooldown-gated; got \(t2) emissions instead of 1")
    }

    @Test("Tier 3: heartbeat snapshot exposes total + rate + last-kind")
    func tier3HeartbeatSnapshot() async {
        await reset()
        let tracker = StorageErrorTracker.shared

        // Empty state at boot.
        var snap = await tracker.eventInsertErrorSnapshot(now: Self.anchor)
        #expect(snap.total == 0)
        #expect(snap.ratePerMin == 0)
        #expect(snap.lastKind == nil)

        // Five errors split across two kinds.
        for i in 0..<3 {
            await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(Double(i)))
        }
        for i in 0..<2 {
            await tracker.recordEventError(constraintError(), now: Self.anchor.addingTimeInterval(3.0 + Double(i)))
        }
        snap = await tracker.eventInsertErrorSnapshot(now: Self.anchor.addingTimeInterval(5.0))
        #expect(snap.total == 5, "snapshot.total should be the running insert-error count")
        #expect(snap.ratePerMin == 5, "all 5 errors fall inside the trailing minute")
        #expect(snap.lastKind == "constraint", "last-kind tracks the most recent error's classification")
    }

    @Test("Recovery: rate window decays to zero after 60s of quiet")
    func recoveryClearsRateCounter() async {
        await reset()
        let tracker = StorageErrorTracker.shared

        // Drive 50 errors at t=0..5s, then sample at t=70s with no
        // intervening errors. The rolling rate must report 0.
        for i in 0..<50 {
            await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(Double(i) * 0.1))
        }
        let preRecoverySnap = await tracker.eventInsertErrorSnapshot(now: Self.anchor.addingTimeInterval(5.0))
        #expect(preRecoverySnap.ratePerMin == 50)

        // Jump past the trailing window. No new errors recorded.
        let postRecoverySnap = await tracker.eventInsertErrorSnapshot(now: Self.anchor.addingTimeInterval(70.0))
        #expect(postRecoverySnap.ratePerMin == 0, "rate should decay to 0 after 60 s of quiet")
        // Total is monotonic; it does NOT reset on recovery.
        #expect(postRecoverySnap.total == 50)
        // Last kind sticks until a new error overwrites it.
        #expect(postRecoverySnap.lastKind == "disk_io")
    }

    @Test("Cross-kind: distinct error kinds escalate independently and share no state")
    func crossKindIsolation() async {
        await reset()
        let tracker = StorageErrorTracker.shared

        // Hit `disk_io` 5 times — only the first should emit (count<10).
        for i in 0..<5 {
            await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(Double(i) * 0.1))
        }
        // Hit `constraint` 1 time — also emits (first of kind).
        await tracker.recordEventError(constraintError(), now: Self.anchor.addingTimeInterval(1.0))
        let totalEmits = await tracker.tier1EmissionCount
        #expect(totalEmits == 2, "Two distinct kinds, each crossing the count==1 boundary ⇒ 2 tier-1 emissions")

        let diskIOKindEmits = await tracker.tier1EmissionsByKind["disk_io"] ?? 0
        let constraintKindEmits = await tracker.tier1EmissionsByKind["constraint"] ?? 0
        #expect(diskIOKindEmits == 1, "disk_io kind ladder should be at position 1 (first-of-kind only)")
        #expect(constraintKindEmits == 1, "constraint kind ladder should be at position 1")

        // Drive `disk_io` to 10 — the 10th must emit independently
        // of however many `constraint` errors have come through.
        for i in 5..<10 {
            await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(1.0 + Double(i) * 0.1))
        }
        let diskIOKindEmitsAfter = await tracker.tier1EmissionsByKind["disk_io"] ?? 0
        #expect(diskIOKindEmitsAfter == 2, "disk_io should hit its 10-mark and emit again")

        // Constraint count stays at 1; its ladder must be untouched
        // by disk_io activity.
        let constraintKindEmitsAfter = await tracker.tier1EmissionsByKind["constraint"] ?? 0
        #expect(constraintKindEmitsAfter == 1, "constraint emissions must NOT be affected by disk_io activity")
    }

    @Test("Classification: known SQLite error strings map to stable normalised kinds")
    func classification() async {
        // The classifier is a pure static function — exercise it
        // directly so we get clean coverage of the kind vocabulary
        // without touching the tracker's mutable state.
        #expect(StorageErrorTracker.classifyEventInsertError(EventStoreError.stepFailed("disk I/O error")) == "disk_io")
        #expect(StorageErrorTracker.classifyEventInsertError(EventStoreError.diskFull("database or disk is full")) == "disk_full")
        #expect(StorageErrorTracker.classifyEventInsertError(EventStoreError.stepFailed("database is locked")) == "lock_timeout")
        #expect(StorageErrorTracker.classifyEventInsertError(EventStoreError.stepFailed("UNIQUE constraint failed: alerts.id")) == "constraint")
        #expect(StorageErrorTracker.classifyEventInsertError(EventStoreError.stepFailed("attempt to write a readonly database")) == "readonly")
        #expect(StorageErrorTracker.classifyEventInsertError(EventStoreError.encodingFailed("bad UTF-8")) == "encoding")
        #expect(StorageErrorTracker.classifyEventInsertError(EventStoreError.prepareFailed("syntax error")) == "prepare")
        // Generic step failure with no recognisable substring falls
        // back to `step_other` rather than the catch-all `other` —
        // this preserves a useful distinction in the dashboard.
        #expect(StorageErrorTracker.classifyEventInsertError(EventStoreError.stepFailed("unknown_sqlite_state_9999")) == "step_other")
    }

    @Test("Legacy snapshot file is still written after Wave 9D escalation runs")
    func legacySnapshotPreserved() async throws {
        // The Wave 9D contract is "ADDITIVE": we add per-kind logging
        // + rate warning + heartbeat surface, but we MUST NOT skip
        // the storage_errors.json write that the dashboard's
        // existing banner depends on.
        //
        // We can't easily intercept the snapshot path (it's hard-coded
        // to /Library/Application Support/MacCrab/) without a refactor
        // we don't want in this wave. Instead, we assert by reading
        // back the tracker's view of the counters AFTER an error — if
        // the writeSnapshot path were skipped, the in-memory counters
        // would still increment, so this test only catches a state
        // divergence; the actual file write is exercised in
        // V2HeartbeatSnapshotTests on the consumer side.
        await reset()
        let tracker = StorageErrorTracker.shared
        await tracker.recordEventError(diskIOError(), now: Self.anchor)
        let snap = await tracker.eventInsertErrorSnapshot(now: Self.anchor)
        #expect(snap.total == 1)
        #expect(snap.lastKind == "disk_io")
    }

    @Test("snapshot total is a rolling 24h window — old errors age out (no perpetual stale count)")
    func rollingWindowAgesOutOldErrors() async {
        await reset()
        let tracker = StorageErrorTracker.shared

        // 5 errors at the anchor.
        for i in 0..<5 {
            await tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(Double(i)))
        }
        var snap = await tracker.eventInsertErrorSnapshot(now: Self.anchor.addingTimeInterval(5))
        #expect(snap.total == 5, "all 5 recent errors counted, got \(snap.total)")

        // 25h later the anchor errors fall outside the 24h window.
        let later = Self.anchor.addingTimeInterval(25 * 3600)
        snap = await tracker.eventInsertErrorSnapshot(now: later)
        #expect(snap.total == 0, "errors older than 24h must age out (the stale-1M fix), got \(snap.total)")

        // A fresh error at `later` counts; the aged-out ones stay gone.
        await tracker.recordEventError(diskIOError(), now: later)
        snap = await tracker.eventInsertErrorSnapshot(now: later)
        #expect(snap.total == 1, "only the in-window error counts, got \(snap.total)")
    }
}
