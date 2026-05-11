// ProcessIdentityResolverTests.swift
// v1.10 TraceGraph (PR-6a) — tests for ProcessIdentityResolver
// per §15.1 of the spec, including Fixture 4 (PID recycle).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: ProcessIdentityResolver")
struct ProcessIdentityResolverTests {

    private func makeIdentity(
        pid: Int32,
        pidversion: UInt32 = 1,
        pathHash: UInt64 = 0xDEADBEEF
    ) -> ProcessIdentity {
        ProcessIdentity(
            auditIdentity: AuditIdentity(
                auid: 501, euid: 501, egid: 20,
                ruid: 501, rgid: 20,
                pid: pid, pidversion: pidversion, asid: 100
            ),
            pathHash: pathHash,
            pid: pid,
            startTime: 1_700_000_000
        )
    }

    @Test("Fresh identity → no recycle, processKey populated")
    func freshObservation() async {
        let resolver = ProcessIdentityResolver()
        let identity = makeIdentity(pid: 1000)
        let result = await resolver.resolve(identity)
        #expect(!result.recycleDetected)
        #expect(result.recycleEvent == nil)
        #expect(result.processKey == identity.processKey)
        #expect(result.identity == identity)
    }

    @Test("Same identity twice → no recycle on either resolution")
    func sameIdentityTwice() async {
        let resolver = ProcessIdentityResolver()
        let identity = makeIdentity(pid: 1001)
        let r1 = await resolver.resolve(identity)
        let r2 = await resolver.resolve(identity)
        #expect(!r1.recycleDetected)
        #expect(!r2.recycleDetected)
        #expect(r1.processKey == r2.processKey)
        let metrics = await resolver.metrics()
        #expect(metrics.pidRecycleRejected == 0)
    }

    /// Fixture 4 — pid 123 process A exits, pid 123 process B starts
    /// with a different pidversion. Must produce two distinct
    /// resolutions and a recycle event.
    @Test("Fixture 4: PID recycle via pidversion mismatch")
    func fixture4_pidversionRecycle() async {
        let resolver = ProcessIdentityResolver()
        let processA = makeIdentity(pid: 123, pidversion: 5)
        let processB = makeIdentity(pid: 123, pidversion: 6)

        let resA = await resolver.resolve(processA)
        let resB = await resolver.resolve(processB)

        #expect(!resA.recycleDetected)
        #expect(resB.recycleDetected)
        #expect(resA.processKey != resB.processKey)

        let event = resB.recycleEvent
        #expect(event != nil)
        #expect(event?.pid == 123)
        #expect(event?.oldProcessKey == resA.processKey)
        #expect(event?.newProcessKey == resB.processKey)
        #expect(event?.oldPidversion == 5)
        #expect(event?.newPidversion == 6)

        let metrics = await resolver.metrics()
        #expect(metrics.pidRecycleRejected == 1)
    }

    @Test("PID recycle via pathHash mismatch (same pid, same pidversion, different exec)")
    func pathHashRecycle() async {
        // This shape matters because audit_token edge cases (rare but
        // documented) could in principle give a stale pidversion across
        // boots. pathHash is the defence-in-depth check that still
        // produces a recycle in that case.
        let resolver = ProcessIdentityResolver()
        let processA = makeIdentity(pid: 200, pidversion: 1, pathHash: 0xAAA)
        let processB = makeIdentity(pid: 200, pidversion: 1, pathHash: 0xBBB)
        _ = await resolver.resolve(processA)
        let resB = await resolver.resolve(processB)
        #expect(resB.recycleDetected)
        #expect(resB.recycleEvent?.oldPathHash == 0xAAA)
        #expect(resB.recycleEvent?.newPathHash == 0xBBB)
    }

    @Test("Different pids resolve independently — no cross-talk")
    func independentPids() async {
        let resolver = ProcessIdentityResolver()
        let a = makeIdentity(pid: 100)
        let b = makeIdentity(pid: 200)
        let c = makeIdentity(pid: 300)
        let resA = await resolver.resolve(a)
        let resB = await resolver.resolve(b)
        let resC = await resolver.resolve(c)
        #expect(!resA.recycleDetected)
        #expect(!resB.recycleDetected)
        #expect(!resC.recycleDetected)
        let metrics = await resolver.metrics()
        #expect(metrics.trackedPids == 3)
        #expect(metrics.pidRecycleRejected == 0)
    }

    @Test("evict(pid:) drops cached identity")
    func evictRemovesCache() async {
        let resolver = ProcessIdentityResolver()
        let a = makeIdentity(pid: 500, pidversion: 1)
        _ = await resolver.resolve(a)
        await resolver.evict(pid: 500)

        // After eviction, a fresh identity at the same pid (even with
        // different pidversion) does NOT count as a recycle from the
        // resolver's perspective — the cache forgot the prior owner.
        // Recycle detection at the rolling-graph level is layered on
        // top via EntityResolver, so this is acceptable behaviour.
        let b = makeIdentity(pid: 500, pidversion: 99)
        let resB = await resolver.resolve(b)
        #expect(!resB.recycleDetected)

        let metrics = await resolver.metrics()
        #expect(metrics.pidRecycleRejected == 0)
    }

    @Test("drainRecycleEvents returns then clears the buffer")
    func drainBuffer() async {
        let resolver = ProcessIdentityResolver()
        _ = await resolver.resolve(makeIdentity(pid: 1, pidversion: 1))
        _ = await resolver.resolve(makeIdentity(pid: 1, pidversion: 2))
        _ = await resolver.resolve(makeIdentity(pid: 1, pidversion: 3))

        let drained1 = await resolver.drainRecycleEvents()
        #expect(drained1.count == 2) // pidversion 1→2 and 2→3

        let drained2 = await resolver.drainRecycleEvents()
        #expect(drained2.isEmpty)
    }

    @Test("Recycle event buffer is bounded at the configured cap")
    func bufferIsBounded() async {
        let cap = 16
        let resolver = ProcessIdentityResolver(recycleEventBufferCap: cap)
        // Generate cap + 5 recycles on the same pid by escalating pidversion.
        for n in 1...(cap + 5) {
            _ = await resolver.resolve(makeIdentity(pid: 7, pidversion: UInt32(n)))
        }
        let drained = await resolver.drainRecycleEvents()
        #expect(drained.count == cap)
        // The retained events should be the most recent ones — buffer
        // drops oldest first.
        let lastEvent = drained.last
        #expect(lastEvent?.newPidversion == UInt32(cap + 5))
    }
}
