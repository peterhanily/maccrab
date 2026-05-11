// EntityResolverTests.swift
// v1.10 TraceGraph (PR-6a) — tests for EntityResolver applying the
// §10.2 merge policy.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: EntityResolver merge policy")
struct EntityResolverTests {

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

    @Test("First observation creates a new entity")
    func createNew() async {
        let resolver = EntityResolver()
        let identity = makeIdentity(pid: 100)
        let outcome = await resolver.merge(identity: identity)
        #expect(outcome == .createdNew(processKey: identity.processKey))

        let entity = await resolver.entity(forKey: identity.processKey)
        #expect(entity?.observationCount == 1)
        #expect(entity?.identity == identity)
    }

    @Test("Repeat observation merges into existing entity")
    func mergeIntoExisting() async {
        let resolver = EntityResolver()
        let identity = makeIdentity(pid: 100)
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let t1 = Date(timeIntervalSince1970: 1_700_000_010)

        let first = await resolver.merge(identity: identity, observedAt: t0)
        let second = await resolver.merge(identity: identity, observedAt: t1)

        #expect(first == .createdNew(processKey: identity.processKey))
        #expect(second == .mergedIntoExisting(processKey: identity.processKey))

        let entity = await resolver.entity(forKey: identity.processKey)
        #expect(entity?.observationCount == 2)
        #expect(entity?.firstSeen == t0)
        #expect(entity?.lastSeen == t1)
    }

    @Test("Out-of-order observation does not move firstSeen forward or lastSeen backward")
    func outOfOrderTimestamps() async {
        let resolver = EntityResolver()
        let identity = makeIdentity(pid: 100)
        let t0 = Date(timeIntervalSince1970: 1_700_000_100)
        let tEarlier = Date(timeIntervalSince1970: 1_700_000_050)

        _ = await resolver.merge(identity: identity, observedAt: t0)
        _ = await resolver.merge(identity: identity, observedAt: tEarlier)

        let entity = await resolver.entity(forKey: identity.processKey)
        // firstSeen records the first observation timestamp at creation;
        // a later out-of-order observation does NOT push it backward
        // (we'd lose the clock-skew evidence). lastSeen does not move
        // backward either.
        #expect(entity?.firstSeen == t0)
        #expect(entity?.lastSeen == t0)
    }

    @Test("PID recycle: same pid, different pidversion → two distinct entities")
    func pidRecycleByPidversion() async {
        let resolver = EntityResolver()
        let processA = makeIdentity(pid: 200, pidversion: 1)
        let processB = makeIdentity(pid: 200, pidversion: 2)

        let outA = await resolver.merge(identity: processA)
        let outB = await resolver.merge(identity: processB)

        #expect(outA == .createdNew(processKey: processA.processKey))
        if case let .pidRecycle(oldKey, newKey) = outB {
            #expect(oldKey == processA.processKey)
            #expect(newKey == processB.processKey)
        } else {
            Issue.record("Expected pidRecycle outcome, got \(outB)")
        }

        // Both entities remain queryable.
        #expect(await resolver.entity(forKey: processA.processKey) != nil)
        #expect(await resolver.entity(forKey: processB.processKey) != nil)

        // The pid index now points to the newer entity.
        #expect(await resolver.canonicalKey(forPid: 200) == processB.processKey)

        let metrics = await resolver.metrics()
        #expect(metrics.pidRecycleRejected == 1)
        #expect(metrics.entityCount == 2)
        #expect(metrics.livePidCount == 1)
    }

    @Test("PID recycle: same pid, different pathHash → two distinct entities")
    func pidRecycleByPathHash() async {
        let resolver = EntityResolver()
        let processA = makeIdentity(pid: 300, pidversion: 1, pathHash: 0xAAA)
        let processB = makeIdentity(pid: 300, pidversion: 1, pathHash: 0xBBB)

        _ = await resolver.merge(identity: processA)
        let outB = await resolver.merge(identity: processB)

        if case let .pidRecycle(oldKey, _) = outB {
            #expect(oldKey == processA.processKey)
        } else {
            Issue.record("Expected pidRecycle outcome, got \(outB)")
        }
    }

    @Test("Different pids do not interact")
    func independentPids() async {
        let resolver = EntityResolver()
        let a = makeIdentity(pid: 100)
        let b = makeIdentity(pid: 200)
        let c = makeIdentity(pid: 300)
        _ = await resolver.merge(identity: a)
        _ = await resolver.merge(identity: b)
        _ = await resolver.merge(identity: c)

        let metrics = await resolver.metrics()
        #expect(metrics.entityCount == 3)
        #expect(metrics.livePidCount == 3)
        #expect(metrics.pidRecycleRejected == 0)
    }

    @Test("releasePidOwnership preserves the entity but drops the pid index")
    func releasePid() async {
        let resolver = EntityResolver()
        let identity = makeIdentity(pid: 400)
        _ = await resolver.merge(identity: identity)
        await resolver.releasePidOwnership(pid: 400)

        // Entity remains addressable by canonical key (still useful as
        // ancestry for an active trace) but the pid index lost it.
        #expect(await resolver.entity(forKey: identity.processKey) != nil)
        #expect(await resolver.canonicalKey(forPid: 400) == nil)

        // A fresh identity at the same pid no longer reports as a recycle
        // because we explicitly released ownership.
        let fresh = makeIdentity(pid: 400, pidversion: 99)
        let outcome = await resolver.merge(identity: fresh)
        #expect(outcome == .createdNew(processKey: fresh.processKey))
    }

    @Test("evict(processKey:) removes the entity and clears its pid index entry")
    func evictRemovesEverything() async {
        let resolver = EntityResolver()
        let identity = makeIdentity(pid: 500)
        _ = await resolver.merge(identity: identity)
        await resolver.evict(processKey: identity.processKey)

        #expect(await resolver.entity(forKey: identity.processKey) == nil)
        #expect(await resolver.canonicalKey(forPid: 500) == nil)
    }

    @Test("Same canonical key from a re-observed merged entity does not count as recycle")
    func sameKeyNoRecycle() async {
        // Specifically verifies that merging into an existing entity
        // doesn't accidentally trip the pid-recycle path when the pid
        // index already points at the same canonical key.
        let resolver = EntityResolver()
        let identity = makeIdentity(pid: 600)
        _ = await resolver.merge(identity: identity)
        _ = await resolver.merge(identity: identity)
        _ = await resolver.merge(identity: identity)

        let metrics = await resolver.metrics()
        #expect(metrics.pidRecycleRejected == 0)
        #expect(metrics.silentMerges == 2)
    }
}
